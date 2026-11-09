use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::LazyLock;

use crate::generic_rules::{mask_generic_rule_strings, mask_rust_test_regions};

pub struct SourceAnalysisContext<'a> {
    raw_sources: &'a BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
    masked_source_lines: BTreeMap<String, Vec<String>>,
    base_sources: BTreeMap<String, String>,
    changed_paths: &'a BTreeSet<String>,
    auxiliary_files: &'a BTreeMap<String, String>,
    changed_base: bool,
}

impl<'a> SourceAnalysisContext<'a> {
    #[cfg(test)]
    pub fn new(
        sources: &'a BTreeMap<String, String>,
        base_sources: &'a BTreeMap<String, String>,
        changed_paths: &'a BTreeSet<String>,
        changed_base: bool,
    ) -> Self {
        static EMPTY_AUXILIARY: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);
        Self::with_auxiliary(
            sources,
            base_sources,
            changed_paths,
            changed_base,
            &EMPTY_AUXILIARY,
        )
    }

    #[cfg(test)]
    pub fn unchanged(sources: &'a BTreeMap<String, String>) -> Self {
        static EMPTY_SOURCES: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);
        static EMPTY_PATHS: LazyLock<BTreeSet<String>> = LazyLock::new(BTreeSet::new);
        Self::new(sources, &EMPTY_SOURCES, &EMPTY_PATHS, false)
    }

    pub fn with_auxiliary(
        sources: &'a BTreeMap<String, String>,
        base_sources: &'a BTreeMap<String, String>,
        changed_paths: &'a BTreeSet<String>,
        changed_base: bool,
        auxiliary_files: &'a BTreeMap<String, String>,
    ) -> Self {
        let raw_sources = sources;
        let sources = sources
            .iter()
            .map(|(path, source)| (path.clone(), mask_test_regions(path, source)))
            .collect::<BTreeMap<_, _>>();
        let base_sources = base_sources
            .iter()
            .map(|(path, source)| (path.clone(), mask_test_regions(path, source)))
            .collect::<BTreeMap<_, _>>();
        let masked_source_lines = sources
            .iter()
            .map(|(path, source)| {
                let lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
                (path.clone(), mask_generic_rule_strings(&lines, path))
            })
            .collect();
        Self {
            raw_sources,
            sources,
            masked_source_lines,
            base_sources,
            changed_paths,
            auxiliary_files,
            changed_base,
        }
    }

    pub fn sources(&self) -> &BTreeMap<String, String> {
        &self.sources
    }

    pub fn raw_sources(&self) -> &BTreeMap<String, String> {
        self.raw_sources
    }

    pub fn masked_lines(&self, path: &str) -> &[String] {
        self.masked_source_lines
            .get(path)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn base_sources(&self) -> &BTreeMap<String, String> {
        &self.base_sources
    }

    pub fn changed_paths(&self) -> &BTreeSet<String> {
        self.changed_paths
    }

    pub fn auxiliary_files(&self) -> &BTreeMap<String, String> {
        self.auxiliary_files
    }

    pub fn has_changed_base(&self) -> bool {
        self.changed_base
    }
}

fn mask_test_regions(path: &str, source: &str) -> String {
    let source = mask_rust_test_regions(path, source);
    if !path.ends_with(".py") {
        return source;
    }

    let lines = source.split('\n').map(str::to_owned).collect::<Vec<_>>();
    let lexical_lines = mask_generic_rule_strings(&lines, path);
    let mut masked = Vec::with_capacity(lines.len());
    let mut delimiter_depth = 0_i32;
    let mut masking = false;

    for (line, lexical) in lines.into_iter().zip(lexical_lines) {
        if !masking {
            masking = is_python_embedded_test_assignment(&lexical);
        }
        if !masking {
            masked.push(line);
            continue;
        }

        let (opens, closes) = python_delimiter_counts(&lexical);
        delimiter_depth += opens - closes;
        masked.push(" ".repeat(line.chars().count()));
        if delimiter_depth <= 0 && !lexical.trim_end().ends_with('\\') {
            delimiter_depth = 0;
            masking = false;
        }
    }

    masked.join("\n")
}

fn is_python_embedded_test_assignment(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.len() == line.len() {
        return false;
    }
    let name_length = trimmed
        .find(|character: char| {
            !(character.is_ascii_uppercase() || character == '_' || character.is_ascii_digit())
        })
        .unwrap_or(trimmed.len());
    let (name, tail) = trimmed.split_at(name_length);
    name.starts_with('_')
        && (name.ends_with("_TEST") || name.ends_with("_TESTS"))
        && tail.trim_start().starts_with('=')
}

fn python_delimiter_counts(line: &str) -> (i32, i32) {
    line.chars()
        .fold((0, 0), |(opens, closes), character| match character {
            '(' | '[' | '{' => (opens + 1, closes),
            ')' | ']' | '}' => (opens, closes + 1),
            _ => (opens, closes),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_rust_test_regions_from_rule_sources() {
        let source = "fn production() {}\n\
#[cfg(test)]\n\
mod tests {\n\
    #[test]\n\
    fn fixture() { let sample = \"TODO: fixture\"; }\n\
}\n\
fn after() {}\n";
        let sources = BTreeMap::from([("src/lib.rs".to_owned(), source.to_owned())]);
        let empty_sources = BTreeMap::new();
        let empty_paths = BTreeSet::new();
        let context = SourceAnalysisContext::with_auxiliary(
            &sources,
            &empty_sources,
            &empty_paths,
            false,
            &empty_sources,
        );
        let analyzed = &context.sources()["src/lib.rs"];
        assert_eq!(context.raw_sources()["src/lib.rs"], source);

        assert!(analyzed.contains("fn production() {}"));
        assert!(analyzed.contains("fn after() {}"));
        assert!(!analyzed.contains("TODO: fixture"));
        assert_eq!(analyzed.lines().count(), source.lines().count());
    }

    #[test]
    fn removes_embedded_python_test_fixtures_from_rule_sources() {
        let source = r#"PRODUCTION_LIMIT = 123456789
class Extractor:
    _TESTS = [{
        'timestamp': 1690403700,
        'description': '''fixture
with delimiters [ignored]''',
    }]
    _TEST = {'timestamp': 1569445289}
    _WEBPAGE_TESTS = [{'timestamp': 1701156004}]
    _TEST_TIMEOUT = 987654321
    def extract(self):
        return 234567891
"#;
        let sources = BTreeMap::from([("extractor.py".to_owned(), source.to_owned())]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let analyzed = &context.sources()["extractor.py"];

        assert_eq!(context.raw_sources()["extractor.py"], source);
        assert!(analyzed.contains("PRODUCTION_LIMIT = 123456789"));
        assert!(analyzed.contains("_TEST_TIMEOUT = 987654321"));
        assert!(analyzed.contains("return 234567891"));
        assert!(!analyzed.contains("1690403700"));
        assert!(!analyzed.contains("1569445289"));
        assert!(!analyzed.contains("1701156004"));
        assert_eq!(analyzed.lines().count(), source.lines().count());
    }
}
