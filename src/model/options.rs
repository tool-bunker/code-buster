use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Text,
    Json,
    Ndjson,
    Markdown,
    Sarif,
    Junit,
    Mermaid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewOptions {
    pub root: PathBuf,
    pub language: Option<String>,
    pub languages: Vec<String>,
    pub format: ReportFormat,
    pub top: i64,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub changed_base: Option<String>,
    pub verbose: bool,
    pub profile: bool,
    pub include_all: bool,
    pub include_tests: bool,
    pub include_examples: bool,
    pub include_vendored: bool,
    pub only: String,
    pub dry_run: bool,
    pub changed_lines: bool,
    pub force: bool,
    pub ci: bool,
    pub allow_empty: bool,
    pub fail_on_issues: bool,
    pub include_advisory: bool,
    pub all_findings: bool,
    pub inactive_rules: bool,
    pub finding_group: String,
    pub baseline: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub cache_enabled: bool,
    pub cache_directory: Option<PathBuf>,
    pub ingest_sarif: Vec<String>,
}

impl Default for PreviewOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            language: None,
            languages: Vec::new(),
            format: ReportFormat::Text,
            top: 0,
            includes: Vec::new(),
            excludes: Vec::new(),
            changed_base: None,
            verbose: false,
            profile: false,
            include_all: false,
            include_tests: false,
            include_examples: false,
            include_vendored: false,
            only: String::new(),
            dry_run: false,
            changed_lines: false,
            ci: false,
            force: false,
            allow_empty: false,
            fail_on_issues: false,
            include_advisory: false,
            all_findings: false,
            inactive_rules: false,
            finding_group: String::new(),
            baseline: None,
            output: None,
            cache_enabled: true,
            cache_directory: None,
            ingest_sarif: Vec::new(),
        }
    }
}
