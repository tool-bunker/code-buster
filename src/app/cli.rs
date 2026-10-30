use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::{ArgAction, Parser};

const COMMANDS: &[(&str, &str)] = &[
    ("summary", "Analyze the repository and show its health."),
    ("review", "Review findings, changes, plans, or actions."),
    (
        "inspect",
        "Explain a file, relationship, or dependency path.",
    ),
    ("graph", "Render the repository dependency graph."),
    ("dead", "Find unreachable production files and exports."),
    ("duplication", "Find repeated source blocks."),
    (
        "quality",
        "Show scores, complexity, hotspots, or structure.",
    ),
    ("rules", "List rules or explain one rule."),
    ("baseline", "Create, update, prune, or inspect a baseline."),
    ("fix", "Preview or apply supported safe fixes."),
    ("init", "Create a starter Code Buster configuration."),
    ("doctor", "Diagnose setup and source discovery."),
    ("config", "Explain configuration or selected files."),
    ("update", "Update the installed Code Buster executable."),
    ("completions", "Generate shell completion data."),
    ("version", "Print version and runtime information."),
];

pub fn usage(color: bool) -> String {
    let mut output = String::new();
    write_styled(&mut output, color, "1;36", "Code Buster");
    output.push_str("\nRepository-aware static analysis across languages and frameworks.\n");

    write_section(&mut output, color, "Usage");
    output.push_str("  cb [command] [options]\n");
    output.push_str("  cb                         Run the default summary\n");

    write_section(&mut output, color, "Commands");
    write_rows(&mut output, color, COMMANDS);

    write_section(&mut output, color, "Change review");
    write_rows(
        &mut output,
        color,
        &[
            (
                "--pr",
                "Review the current branch from its pull-request merge base.",
            ),
            (
                "--changed",
                "Review staged, unstaged, and untracked changes from HEAD.",
            ),
            (
                "--changed-base <REV>",
                "Review changes from a Git revision.",
            ),
            ("--changed-lines", "Keep findings located on changed lines."),
        ],
    );

    write_section(&mut output, color, "Scope");
    write_rows(
        &mut output,
        color,
        &[
            (
                "-r, --root <PATH>",
                "Set the repository root. Default: current directory.",
            ),
            ("-l, --lang <LANG>", "Analyze one language."),
            (
                "--languages <A,B>",
                "Analyze a comma-separated language list.",
            ),
            ("--include <GLOB>", "Include matching paths. Repeatable."),
            ("--exclude <GLOB>", "Exclude matching paths. Repeatable."),
            ("--all", "Include all source classifications."),
            ("--include-tests", "Include test sources."),
            (
                "--include-examples",
                "Include example and benchmark sources.",
            ),
            ("--include-vendored", "Include vendored sources."),
        ],
    );

    write_section(&mut output, color, "Findings and output");
    write_rows(
        &mut output,
        color,
        &[
            ("--advisory", "Show advisory findings in detail."),
            ("--all-findings", "Show actionable and advisory findings."),
            ("--group <GROUP>", "Limit findings to one canonical group."),
            ("--only <RULE>", "Limit findings to one rule or family."),
            ("--inactive", "Include inactive rules when listing rules."),
            (
                "-n, --top <COUNT>",
                "Limit ranked output. Default: no limit.",
            ),
            (
                "--format <FORMAT>",
                "text, json, ndjson, markdown, sarif, junit, or mermaid.",
            ),
            ("--output <PATH>", "Write the report to a file."),
            (
                "--fail-on-issues",
                "Return a failing status when actionable findings exist.",
            ),
            ("--ci", "Use CI behavior and fail on actionable findings."),
            (
                "--allow-empty",
                "Allow analysis with no selected source files.",
            ),
            ("--verbose", "Show scope and analysis-stage details."),
        ],
    );

    write_section(&mut output, color, "Focused views");
    write_rows(
        &mut output,
        color,
        &[
            ("--score", "Show per-file quality scores."),
            ("--complexity", "Show function and cognitive complexity."),
            ("--hotspots", "Show ranked maintenance hotspots."),
            ("--structure", "Show repository structure findings."),
            ("--related", "Show files related to an inspected target."),
            ("--why", "Explain why an inspected target is reachable."),
            (
                "--path",
                "Find a dependency path between inspected targets.",
            ),
            ("--files", "Show files selected by resolved configuration."),
        ],
    );

    write_section(&mut output, color, "Workflow");
    write_rows(
        &mut output,
        color,
        &[
            ("--baseline <PATH>", "Read or write a finding baseline."),
            (
                "--ingest-sarif <PATH>",
                "Import SARIF findings. Repeatable.",
            ),
            ("--profile", "Measure uncached rule-pack execution."),
            (
                "--[no-]cache",
                "Enable or disable the external analysis cache.",
            ),
            ("--cache-dir <PATH>", "Use a custom cache directory."),
            ("--force", "Allow an intentional replacement or update."),
            ("--dry-run", "Preview a write-capable command."),
            ("-h, --help", "Show this help."),
            ("--version", "Print version information."),
        ],
    );

    write_section(&mut output, color, "Examples");
    output.push_str(
        "  cb\n\
         \x20 cb review --pr --advisory\n\
         \x20 cb review --changed\n\
         \x20 cb quality --complexity\n\
         \x20 cb rules rust-unwrap\n",
    );
    output
}

pub const fn argument_usage() -> &'static str {
    "Usage: cb <command> [options]\nRun `cb --help` for commands, options, and examples."
}

fn write_section(output: &mut String, color: bool, title: &str) {
    output.push('\n');
    write_styled(output, color, "1;34", title);
    output.push('\n');
}

fn write_rows(output: &mut String, color: bool, rows: &[(&str, &str)]) {
    const LABEL_WIDTH: usize = 29;
    for (label, description) in rows {
        output.push_str("  ");
        write_styled(output, color, "36", label);
        output.extend(std::iter::repeat_n(
            ' ',
            LABEL_WIDTH.saturating_sub(label.chars().count()),
        ));
        write_styled(output, color, "2", description);
        output.push('\n');
    }
}

fn write_styled(output: &mut String, color: bool, ansi: &str, value: &str) {
    if color {
        let _ = write!(output, "\u{1b}[{ansi}m{value}\u{1b}[0m");
    } else {
        output.push_str(value);
    }
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
    pr: bool,
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
    let changed_base = if parsed.pr {
        Some(resolve_pull_request_base(Path::new(&parsed.root))?)
    } else if parsed.changed {
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
    validate_exclusive_options(command, "review", &[("--pr", parsed.pr)])?;
    if parsed.pr && (parsed.changed || parsed.changed_base.is_some()) {
        return Err("--pr cannot be combined with --changed or --changed-base".to_owned());
    }
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

fn resolve_pull_request_base(root: &Path) -> Result<String, String> {
    for target in pull_request_base_candidates(root) {
        if let Some(merge_base) = git_stdout(root, &["merge-base", "HEAD", &target]) {
            return Ok(merge_base);
        }
    }
    Err(
        "could not resolve the pull-request base; fetch the target branch or use --changed-base <revision>"
            .to_owned(),
    )
}

fn pull_request_base_candidates(root: &Path) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(base) = env::var_os("GITHUB_BASE_REF").and_then(|value| value.into_string().ok()) {
        add_base_ref_candidates(&mut candidates, &base);
    }
    if let Some(remote_head) = git_stdout(
        root,
        &[
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ],
    ) {
        add_candidate(&mut candidates, remote_head);
    }
    for fallback in ["origin/main", "origin/master", "main", "master"] {
        add_candidate(&mut candidates, fallback.to_owned());
    }
    candidates
}

fn add_base_ref_candidates(candidates: &mut Vec<String>, base: &str) {
    let base = base
        .trim()
        .strip_prefix("refs/heads/")
        .unwrap_or(base.trim());
    if base.starts_with("origin/") {
        add_candidate(candidates, base.to_owned());
    } else {
        add_candidate(candidates, format!("origin/{base}"));
        add_candidate(candidates, base.to_owned());
    }
}

fn add_candidate(candidates: &mut Vec<String>, candidate: String) {
    if !candidate.is_empty() && !candidate.starts_with('-') && !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
}

fn git_stdout(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
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

#[cfg(test)]
mod tests {
    use super::usage;

    #[test]
    fn help_color_is_explicit_and_preserves_content() {
        let plain = usage(false);
        let colored = usage(true);

        assert!(!plain.contains("\u{1b}["));
        assert!(colored.contains("\u{1b}[1;36mCode Buster\u{1b}[0m"));
        assert!(plain.contains("cb review --pr --advisory"));
        assert!(colored.contains("cb review --pr --advisory"));
    }
}
