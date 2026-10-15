use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::source_analysis_context::SourceAnalysisContext;

pub struct SemanticDiff {
    pub files: Vec<SemanticFileDiff>,
}

impl SemanticDiff {
    pub fn from_context(context: &SourceAnalysisContext<'_>) -> Self {
        let files = context
            .changed_paths()
            .iter()
            .filter_map(|path| {
                let after = context.sources().get(path)?;
                source_extension(path).then(|| {
                    SemanticFileDiff::new(
                        path.clone(),
                        context
                            .base_sources()
                            .get(path)
                            .cloned()
                            .unwrap_or_default(),
                        after.clone(),
                    )
                })
            })
            .collect();
        Self { files }
    }

    pub fn production_files(&self) -> impl Iterator<Item = &SemanticFileDiff> {
        self.files.iter().filter(|file| !file.is_test)
    }

    pub fn test_files(&self) -> impl Iterator<Item = &SemanticFileDiff> {
        self.files.iter().filter(|file| file.is_test)
    }

    pub fn is_focused(&self) -> bool {
        self.production_files().count() <= 5
    }
}

pub struct SemanticFileDiff {
    pub path: String,
    pub before: String,
    pub after: String,
    pub added_lines: Vec<SemanticLine>,
    pub removed_lines: Vec<SemanticLine>,
    pub is_test: bool,
}

impl SemanticFileDiff {
    fn new(path: String, before: String, after: String) -> Self {
        let added_lines = line_difference(&after, &before);
        let removed_lines = line_difference(&before, &after);
        let is_test = TEST_PATH.is_match(&path.replace('\\', "/"));
        Self {
            path,
            before,
            after,
            added_lines,
            removed_lines,
            is_test,
        }
    }

    pub fn concepts(&self) -> BTreeSet<String> {
        self.path
            .split(['/', '_', '.', '-'])
            .map(str::to_ascii_lowercase)
            .filter(|part| part.len() >= 3 && !IGNORED_CONCEPTS.contains(&part.as_str()))
            .collect()
    }

    pub fn behavior_additions(&self) -> usize {
        self.added_lines
            .iter()
            .filter(|line| BEHAVIOR_LINE.is_match(&line.text))
            .count()
    }

    pub fn declaration_additions(&self) -> usize {
        self.added_lines
            .iter()
            .filter(|line| DECLARATION_LINE.is_match(&line.text))
            .count()
    }

    pub fn style_only_edits(&self) -> usize {
        let mut removed = BTreeMap::<String, usize>::new();
        for line in &self.removed_lines {
            let normalized = style_shape(&line.text);
            if !normalized.is_empty() {
                *removed.entry(normalized).or_default() += 1;
            }
        }
        let mut matches = 0;
        for line in &self.added_lines {
            let normalized = style_shape(&line.text);
            let available = removed.get(&normalized).copied().unwrap_or_default();
            if !normalized.is_empty() && available > 0 {
                matches += 1;
                removed.insert(normalized, available - 1);
            }
        }
        matches
    }
}

#[derive(Clone)]
pub struct SemanticLine {
    pub number: usize,
    pub text: String,
}

fn line_difference(source: &str, other: &str) -> Vec<SemanticLine> {
    let mut available = BTreeMap::<String, usize>::new();
    for line in other.split('\n') {
        let normalized = line.trim();
        if !normalized.is_empty() {
            *available.entry(normalized.to_owned()).or_default() += 1;
        }
    }
    let mut result = Vec::new();
    for (index, line) in source.split('\n').enumerate() {
        let normalized = line.trim();
        if normalized.is_empty() {
            continue;
        }
        let count = available.get(normalized).copied().unwrap_or_default();
        if count > 0 {
            available.insert(normalized.to_owned(), count - 1);
        } else {
            result.push(SemanticLine {
                number: index + 1,
                text: line.to_owned(),
            });
        }
    }
    result
}

fn style_shape(line: &str) -> String {
    let quoted = STYLE_QUOTES.replace_all(line.trim(), "Q");
    let spaced = STYLE_WHITESPACE.replace_all(&quoted, " ");
    let declarations = STYLE_DECLARATION.replace_all(&spaced, "");
    STYLE_TYPE.replace_all(&declarations, "").trim().to_owned()
}

fn source_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{}", value.to_ascii_lowercase()))
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension.as_str()))
}

static TEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(?:test|tests|spec|specs|__tests__)(/|$)|(?:_test|\.test|\.spec)\.")
        .unwrap()
});
static BEHAVIOR_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:if|else|for|while|switch|case|return|throw|await|yield|new)\b|[=!<>]=|\?\?")
        .unwrap()
});
static DECLARATION_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:abstract\s+)?(?:interface|class|mixin|protocol|trait|enum|typedef|type|def|fun|function)\b").unwrap()
});
static STYLE_QUOTES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"[\"']"#).unwrap());
static STYLE_WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static STYLE_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:final|const|var)\s+").unwrap());
static STYLE_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s*:\s*[A-Za-z_$][\w$<>,?\[\]. ]*").unwrap());

const IGNORED_CONCEPTS: &[&str] = &[
    "lib", "src", "test", "tests", "spec", "main", "index", "dart", "java",
];
const SOURCE_EXTENSIONS: &[&str] = &[
    ".c", ".cc", ".cpp", ".cs", ".dart", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt",
    ".kts", ".lua", ".m", ".mm", ".mojo", ".nim", ".php", ".py", ".rs", ".swift", ".ts", ".tsx",
    ".wren",
];
