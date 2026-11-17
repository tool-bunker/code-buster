use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::OnceLock;

use crate::generic_rules::{mask_generic_rule_strings, mask_rust_test_regions};

pub struct SourceAnalysisContext<'a> {
    raw_sources: &'a BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
    masked_source_lines: BTreeMap<String, OnceLock<Vec<String>>>,
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
            .map(|(path, source)| (path.clone(), mask_test_regions(path, source).into_owned()))
            .collect::<BTreeMap<_, _>>();
        let base_sources = base_sources
            .iter()
            .map(|(path, source)| (path.clone(), mask_test_regions(path, source).into_owned()))
            .collect::<BTreeMap<_, _>>();
        let masked_source_lines = sources
            .keys()
            .map(|path| (path.clone(), OnceLock::new()))
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
        let Some(masked) = self.masked_source_lines.get(path) else {
            return &[];
        };
        masked.get_or_init(|| mask_generic_rule_strings(&self.sources[path], path))
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

pub(crate) fn mask_test_regions<'a>(path: &str, source: &'a str) -> Cow<'a, str> {
    if path.ends_with(".rs") {
        return Cow::Owned(mask_rust_test_regions(path, source));
    }
    if !path.ends_with(".py") || !source.contains("_TEST") {
        return Cow::Borrowed(source);
    }

    let lexical_lines = mask_generic_rule_strings(source, path);
    let mut masked = Vec::with_capacity(lexical_lines.len());
    let mut delimiter_depth = 0_i32;
    let mut masking = false;

    for (line, lexical) in source.split('\n').zip(lexical_lines) {
        if !masking {
            masking = is_python_embedded_test_assignment(&lexical);
        }
        if !masking {
            masked.push(Cow::Borrowed(line));
            continue;
        }

        let (opens, closes) = python_delimiter_counts(&lexical);
        delimiter_depth += opens - closes;
        masked.push(Cow::Owned(" ".repeat(line.chars().count())));
        if delimiter_depth <= 0 && !lexical.trim_end().ends_with('\\') {
            delimiter_depth = 0;
            masking = false;
        }
    }

    Cow::Owned(masked.join("\n"))
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
        let masked = context.masked_lines("src/lib.rs").join("\n");
        assert!(masked.contains("fn production() {}"));
        assert!(masked.contains("fn after() {}"));
        assert!(!masked.contains("fn fixture()"));
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

    #[test]
    fn masked_lines_keep_distinct_context_sources_for_the_same_path() {
        let first_sources =
            BTreeMap::from([("src/main.ts".to_owned(), "first_call();\n".to_owned())]);
        let second_sources =
            BTreeMap::from([("src/main.ts".to_owned(), "second_call();\n".to_owned())]);
        let first = SourceAnalysisContext::unchanged(&first_sources);
        let second = SourceAnalysisContext::unchanged(&second_sources);

        assert_eq!(first.masked_lines("src/main.ts"), ["first_call();", ""]);
        assert_eq!(second.masked_lines("src/main.ts"), ["second_call();", ""]);
        assert_eq!(first.masked_lines("src/main.ts"), ["first_call();", ""]);
    }

    #[test]
    fn preserves_cooked_multiline_escape_widths_crlf_and_final_empty_line() {
        let body = "é\\\"still";
        let source = format!("text = \"\"\"{body}\r\n中 end\"\"\"\r\nafter = 12345678\r\n");
        let sources = BTreeMap::from([
            ("source.py".to_owned(), source.clone()),
            ("source.dart".to_owned(), source),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let expected = vec![
            format!("text = {}", " ".repeat(3 + body.len() + 1)),
            format!("{}\r", " ".repeat("中 end\"\"\"".len())),
            "after = 12345678\r".to_owned(),
            String::new(),
        ];
        assert_eq!(context.masked_lines("source.py"), expected);
        assert_eq!(context.masked_lines("source.dart"), expected);
    }

    #[test]
    fn concurrent_mask_requests_keep_file_sources_and_multiline_state_separate() {
        let sources = BTreeMap::from([
            (
                "first.py".to_owned(),
                "first_call()\ntext = '''hidden\nstill hidden'''\nafter_first()\n".to_owned(),
            ),
            (
                "second.py".to_owned(),
                "second_call()\ntext = \"\"\"other hidden\nalso hidden\"\"\"\nafter_second()\n"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);
        let expected = [
            (
                "first.py",
                vec![
                    "first_call()".to_owned(),
                    format!("text = {}", " ".repeat(9)),
                    " ".repeat(15),
                    "after_first()".to_owned(),
                    String::new(),
                ],
            ),
            (
                "second.py",
                vec![
                    "second_call()".to_owned(),
                    format!("text = {}", " ".repeat(15)),
                    " ".repeat(14),
                    "after_second()".to_owned(),
                    String::new(),
                ],
            ),
        ];
        let barrier = std::sync::Barrier::new(8);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    for (path, lines) in &expected {
                        assert_eq!(context.masked_lines(path), lines);
                    }
                    assert!(context.masked_lines("missing.py").is_empty());
                });
            }
        });
    }
}
