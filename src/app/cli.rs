use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
const USAGE_HEADER: &str = "Usage: cb <command> [options]\nCommands: summary review inspect graph dead duplication quality rules baseline fix init doctor config update completions version";

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
        ("    --format", "(text, json, ndjson, markdown, sarif, junit, mermaid; review also supports plan and actions)"),
        ("    --include", ""),
        ("    --exclude", ""),
        ("    --only", ""),
        ("    --score", "Show per-file quality scores."),
        ("    --complexity", "Show complexity findings."),
        ("    --hotspots", "Show ranked maintenance hotspots."),
        ("    --structure", "Show repository structure findings."),
        ("    --related", "Show files related to an inspected target."),
        ("    --why", "Explain why an inspected target is reachable."),
        ("    --path", "Find a dependency path between two inspected targets."),
        ("    --files", "Show files selected by the resolved configuration."),
        ("    --baseline", ""),
        ("    --ingest-sarif", ""),
        ("    --output", ""),
        ("    --changed-base", ""),
        ("    --changed", ""),
        ("    --changed-lines", ""),
        ("    --fail-on-issues", ""),
        ("    --verbose", ""),
        (
            "    --profile",
            "Measure uncached rule-pack execution and print a timing profile.",
        ),
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
    Quality(PreviewOptions, QualityView),
    Review(PreviewOptions, ReviewView),
    Baseline(RepositoryViewOptions),
    Fix(PreviewOptions),
    Config(ConfigOptions),
    ConfigFiles(PreviewOptions),
    Completions(String),
    Dead(PreviewOptions),
    Graph(PreviewOptions),
    Rules(RepositoryViewOptions),
    Inspect(RepositoryViewOptions, InspectView),
    Doctor(PreviewOptions),
    Duplication(PreviewOptions),
    Init(InitOptions),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewView {
    Findings,
    Plan,
    Actions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualityView {
    Overview,
    Score,
    Complexity,
    Hotspots,
    Structure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectView {
    Details,
    Related,
    Why,
    Path,
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
    profile: bool,
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
    #[arg(long)]
    score: bool,
    #[arg(long)]
    complexity: bool,
    #[arg(long)]
    hotspots: bool,
    #[arg(long)]
    structure: bool,
    #[arg(long)]
    related: bool,
    #[arg(long)]
    why: bool,
    #[arg(long)]
    path: bool,
    #[arg(long)]
    files: bool,
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
    let cache_enabled = analysis_cache_enabled(&parsed)?;
    validate_view_options(&parsed)?;
    let (format, review_view) = command_report_format(parsed.command.as_deref(), &parsed.format)?;
    let quality_view = quality_view(&parsed);
    let inspect_view = inspect_view(&parsed);
    let config_files = parsed.files;
    let command = parsed.command;
    let targets = parsed.targets;
    let changed_base = if parsed.changed {
        Some("HEAD".to_owned())
    } else {
        parsed.changed_base
    };
    let mut options = PreviewOptions {
        root: PathBuf::from(parsed.root),
        language: parsed.language,
        languages: parsed.languages,
        format,
        top: parsed.top.parse().unwrap_or(0),
        includes: parsed.include,
        excludes: parsed.exclude,
        changed_base,
        verbose: parsed.verbose,
        profile: parsed.profile,
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
    validate_analysis_options(&options, command.as_deref())?;

    match command.as_deref() {
        Some("version") => Ok(Command::Version),
        Some("summary") => Ok(Command::Summary(options)),
        Some("update") => Ok(Command::Update(options)),
        Some("quality") => Ok(Command::Quality(options, quality_view)),
        Some("review") => {
            if options.changed_base.is_some() {
                options.changed_lines = true;
            }
            Ok(Command::Review(options, review_view))
        }
        Some("baseline") => Ok(Command::Baseline(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("fix") => Ok(Command::Fix(options)),
        Some("completions") => Ok(Command::Completions(
            targets
                .first()
                .cloned()
                .unwrap_or_else(|| "bash".to_owned()),
        )),
        Some("dead") => Ok(Command::Dead(options)),
        Some("graph") => Ok(Command::Graph(options)),
        Some("rules") => Ok(Command::Rules(RepositoryViewOptions {
            common: options,
            targets,
        })),
        Some("inspect") => Ok(Command::Inspect(
            RepositoryViewOptions {
                common: options,
                targets,
            },
            inspect_view,
        )),
        Some("duplication") => Ok(Command::Duplication(options)),
        Some("doctor") => Ok(Command::Doctor(options)),
        Some("init") => Ok(Command::Init(InitOptions {
            root: options.root,
            target: targets.into_iter().next().map(PathBuf::from),
            force: options.force,
        })),
        Some("config") if config_files => Ok(Command::ConfigFiles(options)),
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

fn command_report_format(
    command: Option<&str>,
    value: &str,
) -> Result<(ReportFormat, ReviewView), String> {
    match (command, value) {
        (Some("review"), "plan") => Ok((ReportFormat::Text, ReviewView::Plan)),
        (Some("review"), "actions") => Ok((ReportFormat::Json, ReviewView::Actions)),
        (_, "plan" | "actions") => Err(format!("--format {value} is only supported by cb review")),
        _ => Ok((report_format(value)?, ReviewView::Findings)),
    }
}

fn quality_view(parsed: &ParsedArguments) -> QualityView {
    if parsed.score {
        QualityView::Score
    } else if parsed.complexity {
        QualityView::Complexity
    } else if parsed.hotspots {
        QualityView::Hotspots
    } else if parsed.structure {
        QualityView::Structure
    } else {
        QualityView::Overview
    }
}

fn inspect_view(parsed: &ParsedArguments) -> InspectView {
    if parsed.related {
        InspectView::Related
    } else if parsed.why {
        InspectView::Why
    } else if parsed.path {
        InspectView::Path
    } else {
        InspectView::Details
    }
}

fn validate_view_options(parsed: &ParsedArguments) -> Result<(), String> {
    let command = parsed.command.as_deref();
    validate_exclusive_options(
        command,
        "quality",
        &[
            ("--score", parsed.score),
            ("--complexity", parsed.complexity),
            ("--hotspots", parsed.hotspots),
            ("--structure", parsed.structure),
        ],
    )?;
    validate_exclusive_options(
        command,
        "inspect",
        &[
            ("--related", parsed.related),
            ("--why", parsed.why),
            ("--path", parsed.path),
        ],
    )?;
    validate_exclusive_options(command, "config", &[("--files", parsed.files)])?;
    if parsed.files && !parsed.targets.is_empty() {
        return Err("cb config --files does not accept a config action".to_owned());
    }
    Ok(())
}

fn validate_exclusive_options(
    command: Option<&str>,
    expected_command: &str,
    options: &[(&str, bool)],
) -> Result<(), String> {
    let selected = options
        .iter()
        .filter_map(|(name, enabled)| enabled.then_some(*name))
        .collect::<Vec<_>>();
    if selected.len() > 1 {
        return Err(format!("{} are mutually exclusive", selected.join(", ")));
    }
    if let Some(option) = selected.first()
        && command != Some(expected_command)
    {
        return Err(format!(
            "{option} is only supported by cb {expected_command}"
        ));
    }
    Ok(())
}

fn analysis_cache_enabled(parsed: &ParsedArguments) -> Result<bool, String> {
    if parsed.profile && parsed.cache {
        return Err("--profile cannot be combined with --cache".to_owned());
    }
    if parsed.profile && parsed.cache_dir.is_some() {
        return Err("--profile cannot be combined with --cache-dir".to_owned());
    }
    Ok(!parsed.no_cache && !parsed.profile)
}

fn validate_analysis_options(
    options: &PreviewOptions,
    command: Option<&str>,
) -> Result<(), String> {
    if !options.cache_enabled && options.cache_directory.is_some() {
        return Err("--no-cache cannot be combined with --cache-dir".to_owned());
    }
    if options.profile && !matches!(command, None | Some("summary")) {
        return Err("--profile is only supported by cb summary".to_owned());
    }
    if options.profile && !matches!(&options.format, ReportFormat::Text | ReportFormat::Json) {
        return Err("--profile requires --format text or --format json".to_owned());
    }
    Ok(())
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
