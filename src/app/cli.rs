use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
const USAGE_HEADER: &str = "Usage: cb <command> [options]\nCommands: summary graph dead duplication structure clusters complexity flags hotspots inspect related why path score quality plan actions review pr doctor preview explain rules config baseline fix init test version update completions";

pub fn usage() -> String {
    format!("{USAGE_HEADER}\n{}", argument_usage())
}

pub fn argument_usage() -> String {
    [
        ("-r, --root", "(defaults to \".\")"),
        ("-l, --lang", ""),
        ("    --language", ""),
        ("    --languages=<LANG,LANG>", ""),
        ("-n, --top", "(defaults to \"0\")"),
        ("    --format", "(defaults to \"text\")"),
        ("    --include", ""),
        ("    --exclude", ""),
        ("    --only", ""),
        ("    --baseline", ""),
        ("    --ingest-sarif", ""),
        ("    --output", ""),
        ("    --changed-base", ""),
        ("    --changed", ""),
        ("    --changed-lines", ""),
        ("    --fail-on-issues", ""),
        ("    --verbose", ""),
        ("    --ci", ""),
        ("    --allow-empty", ""),
        (
            "    --[no-]cache",
            "Reuse analysis results from the external user cache.",
        ),
        ("", "(defaults to on)"),
        (
            "    --cache-dir=<PATH>",
            "Store analysis cache files in PATH instead of the user cache.",
        ),
        ("    --all", ""),
        ("    --advisory", ""),
        ("    --all-findings", ""),
        ("    --group", ""),
        ("    --inactive", ""),
        ("    --include-tests", ""),
        ("    --include-examples", ""),
        ("    --include-vendored", ""),
        ("    --force", ""),
        ("    --dry-run", ""),
        ("-h, --help", ""),
        ("    --version", ""),
    ]
    .into_iter()
    .map(|(option, description)| format!("{option:<31}{description}"))
    .collect::<Vec<_>>()
    .join("\n")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Version,
    Summary(PreviewOptions),
    Update(PreviewOptions),
    Preview(PreviewOptions),
    Score(PreviewOptions),
    Quality(PreviewOptions),
    Plan(PreviewOptions),
    Actions(PreviewOptions),
    Review(PreviewOptions),
    Pr(PreviewOptions),
    Baseline(RepositoryViewOptions),
    Fix(PreviewOptions),
    Test(PreviewOptions),
    Config(ConfigOptions),
    Clusters(PreviewOptions),
    Completions(String),
    Complexity(PreviewOptions),
    Dead(PreviewOptions),
    Flags(PreviewOptions),
    Graph(PreviewOptions),
    Hotspots(PreviewOptions),
    Rules(PreviewOptions),
    Explain(RepositoryViewOptions),
    Inspect(RepositoryViewOptions),
    Related(RepositoryViewOptions),
    Why(RepositoryViewOptions),
    Path(RepositoryViewOptions),
    Doctor(PreviewOptions),
    Duplication(PreviewOptions),
    Init(InitOptions),
    Structure(PreviewOptions),
}

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
pub struct InitOptions {
    pub root: PathBuf,
    pub target: Option<PathBuf>,
    pub force: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryViewOptions {
    pub common: PreviewOptions,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigOptions {
    pub root: PathBuf,
    pub language: Option<String>,
    pub languages: Vec<String>,
    pub format: ReportFormat,
    pub target: Option<String>,
    pub only: String,
    pub dry_run: bool,
    pub changed_lines: bool,
    pub include_all: bool,
    pub include_tests: bool,
    pub include_examples: bool,
    pub include_vendored: bool,
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

#[derive(Debug, Parser)]
#[command(name = "cb", disable_help_flag = true, disable_version_flag = true)]
struct ParsedArguments {
    #[arg(short = 'r', long, default_value = ".")]
    root: String,
    #[arg(short = 'l', long = "lang", visible_alias = "language")]
    language: Option<String>,
    #[arg(long, value_delimiter = ',')]
    languages: Vec<String>,
    #[arg(
        short = 'n',
        long = "top",
        default_value = "0",
        allow_hyphen_values = true
    )]
    top: String,
    #[arg(long, default_value = "text")]
    format: String,
    #[arg(long)]
    include: Vec<String>,
    #[arg(long)]
    exclude: Vec<String>,
    #[arg(long)]
    only: Option<String>,
    #[arg(long)]
    baseline: Option<String>,
    #[arg(long, value_delimiter = ',')]
    ingest_sarif: Vec<String>,
    #[arg(long)]
    output: Option<String>,
    #[arg(long)]
    changed_base: Option<String>,
    #[arg(long)]
    changed: bool,
    #[arg(long)]
    changed_lines: bool,
    #[arg(long)]
    fail_on_issues: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(long)]
    ci: bool,
    #[arg(long)]
    allow_empty: bool,
    #[arg(long = "cache", action = ArgAction::SetTrue)]
    cache: bool,
    #[arg(long = "no-cache", action = ArgAction::SetTrue)]
    no_cache: bool,
    #[arg(long)]
    cache_dir: Option<String>,
    #[arg(long = "all")]
    include_all: bool,
    #[arg(long)]
    advisory: bool,
    #[arg(long)]
    all_findings: bool,
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    inactive: bool,
    #[arg(long)]
    include_tests: bool,
    #[arg(long)]
    include_examples: bool,
    #[arg(long)]
    include_vendored: bool,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(value_name = "COMMAND")]
    command: Option<String>,
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "-h" || argument == "--help")
    {
        return Ok(Command::Help);
    }
    if arguments.iter().any(|argument| argument == "--version") {
        return Ok(Command::Version);
    }
    let parsed =
        ParsedArguments::try_parse_from(std::iter::once(OsString::from("cb")).chain(arguments))
            .map_err(|error| error.to_string().trim_end().to_owned())?;
    let command = parsed.command;
    let targets = parsed.targets;
    let changed_base = if parsed.changed {
        Some("HEAD".to_owned())
    } else {
        parsed.changed_base
    };
    let cache_enabled = !parsed.no_cache;
    let _explicit_cache = parsed.cache;
    let mut options = PreviewOptions {
        root: PathBuf::from(parsed.root),
        language: parsed.language,
        languages: parsed.languages,
        format: report_format(&parsed.format)?,
        top: parsed.top.parse().unwrap_or(0),
        includes: parsed.include,
        excludes: parsed.exclude,
        changed_base,
        verbose: parsed.verbose,
        include_all: parsed.include_all,
        include_tests: parsed.include_tests,
        include_examples: parsed.include_examples,
        include_vendored: parsed.include_vendored,
        only: parsed.only.unwrap_or_default(),
        dry_run: parsed.dry_run,
        changed_lines: parsed.changed_lines,
        ci: parsed.ci,
        force: parsed.force,
        allow_empty: parsed.allow_empty,
        fail_on_issues: parsed.fail_on_issues || parsed.ci,
        include_advisory: parsed.advisory,
        all_findings: parsed.all_findings,
        inactive_rules: parsed.inactive,
        finding_group: parsed.group.unwrap_or_default(),
        baseline: parsed.baseline.map(PathBuf::from),
        output: parsed.output.map(PathBuf::from),
        cache_enabled,
        cache_directory: parsed.cache_dir.map(PathBuf::from),
        ingest_sarif: parsed.ingest_sarif,
    };
    if !options.cache_enabled && options.cache_directory.is_some() {
        return Err("--no-cache cannot be combined with --cache-dir".to_owned());
    }

    match command.as_deref() {
        Some("version") => Ok(Command::Version),
        Some("summary") => Ok(Command::Summary(options)),
        Some("preview") => Ok(Command::Preview(options)),
        Some("score") => Ok(Command::Score(options)),
        Some("quality") => Ok(Command::Quality(options)),
        Some("plan") => Ok(Command::Plan(options)),
        Some("actions") => Ok(Command::Actions(options)),
        Some("review") => Ok(Command::Review(options)),
        Some("pr") => {
            if options.changed_base.is_some() {
                options.changed_lines = true;
            }
            Ok(Command::Pr(options))
        }
        Some("baseline") => Ok(Command::Baseline(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("fix") => Ok(Command::Fix(options)),
        Some("test") => Ok(Command::Test(options)),
        Some("completions") => Ok(Command::Completions(
            targets
                .first()
                .cloned()
                .unwrap_or_else(|| "bash".to_owned()),
        )),
        Some("clusters") => Ok(Command::Clusters(options)),
        Some("dead") => Ok(Command::Dead(options)),
        Some("complexity") => Ok(Command::Complexity(options)),
        Some("flags") => Ok(Command::Flags(options)),
        Some("graph") => Ok(Command::Graph(options)),
        Some("hotspots") => Ok(Command::Hotspots(options)),
        Some("rules") => Ok(Command::Rules(options)),
        Some("update") => Ok(Command::Update(options)),
        Some("explain") => Ok(Command::Explain(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("inspect") => Ok(Command::Inspect(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("related") => Ok(Command::Related(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("why") => Ok(Command::Why(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("path") => Ok(Command::Path(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("structure") => Ok(Command::Structure(options)),
        Some("duplication") => Ok(Command::Duplication(options)),
        Some("doctor") => Ok(Command::Doctor(options)),
        Some("init") => Ok(Command::Init(InitOptions {
            root: options.root,
            target: targets.into_iter().next().map(PathBuf::from),
            force: options.force,
        })),
        Some("config") => Ok(Command::Config(ConfigOptions {
            root: options.root,
            language: options.language,
            languages: options.languages,
            format: options.format,
            target: targets.into_iter().next(),
            only: options.only,
            dry_run: options.dry_run,
            changed_lines: options.changed_lines,
            include_all: options.include_all,
            include_tests: options.include_tests,
            include_examples: options.include_examples,
            include_vendored: options.include_vendored,
        })),
        Some(value) => Err(format!("Unknown Code Buster command: {value}")),
        None => Ok(Command::Summary(options)),
    }
}

fn report_format(value: &str) -> Result<ReportFormat, String> {
    match value {
        "text" => Ok(ReportFormat::Text),
        "json" => Ok(ReportFormat::Json),
        "ndjson" => Ok(ReportFormat::Ndjson),
        "markdown" => Ok(ReportFormat::Markdown),
        "sarif" => Ok(ReportFormat::Sarif),
        "junit" => Ok(ReportFormat::Junit),
        "mermaid" => Ok(ReportFormat::Mermaid),
        _ => Err(format!("Unknown Code Buster report format: {value}")),
    }
}
