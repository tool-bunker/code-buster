use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use std::process::Command;
use std::time::Instant;

use crate::analysis_cache::{AnalysisCache, FindingCacheInputs};
use crate::analysis_engine;
use crate::cli::PreviewOptions;
use crate::discovery::{AnalysisProfile, PreparedPreview, is_builtin_production_path, prepare};
use crate::engine::execution_plan::ExecutionPlan;
use crate::finding_controls;
use crate::findings::Finding;
use crate::report::{FindingReport, render};
use crate::reporting::progress::AnalysisProgress;
use crate::repository_contract_rules;
use crate::repository_defaults::RepositoryMetadataFile;
use crate::rule_catalog;
use crate::sarif_ingestion;
use crate::source_analysis_context::SourceAnalysisContext;

pub enum SummaryOutcome {
    Success,
    Empty,
    Findings,
}

pub(crate) struct AnalysisRun {
    pub prepared: PreparedPreview,
    pub findings: Vec<Finding>,
    pub actionable_findings: Vec<Finding>,
    pub actionable_count: usize,
    pub advisory_summary: BTreeMap<String, usize>,
}

pub(crate) fn analyze(options: &PreviewOptions) -> Result<AnalysisRun, String> {
    analyze_for(options, "summary")
}

// code-buster-ignore complex-function: one ordered pipeline owns shared timing, cache, and report state.
fn analyze_for(options: &PreviewOptions, cache_command: &str) -> Result<AnalysisRun, String> {
    let progress = AnalysisProgress::new(options);
    let started = Instant::now();
    let mut stage_durations = BTreeMap::new();
    let mut prepared = prepare(options)?;
    let full_prepared = if options.changed_base.is_some() {
        let mut full_options = options.clone();
        full_options.changed_base = None;
        Some(prepare(&full_options)?)
    } else {
        None
    };
    let analysis_prepared = full_prepared.as_ref().unwrap_or(&prepared);
    let changed_paths = prepared.changed_paths.clone();
    let base_sources = load_base_sources(
        Path::new(&analysis_prepared.root),
        options.changed_base.as_deref(),
        &changed_paths,
    );
    progress.set_phase("Loading project metadata…");
    let mut auxiliary = collect_auxiliary_files(&analysis_prepared.metadata_files);
    collect_flutter_asset_existence(
        Path::new(&analysis_prepared.root),
        &analysis_prepared.sources,
        &mut auxiliary,
    );
    auxiliary.extend(repository_contract_rules::manifest_existence_markers(
        Path::new(&analysis_prepared.root),
        &auxiliary,
    ));
    if let Some(base) = options.changed_base.as_deref()
        && let Some(package) = git_file(Path::new(&analysis_prepared.root), base, "package.json")
    {
        auxiliary.insert("@base/package.json".to_owned(), package);
    }
    stage_durations.insert("preparation".to_owned(), started.elapsed().as_millis());

    progress.set_phase("Building dependency graph…");
    let graph_started = Instant::now();
    let mut cache =
        AnalysisCache::new(options, Path::new(&analysis_prepared.root)).with_finding_inputs(
            FindingCacheInputs::new(&base_sources, &changed_paths, &auxiliary),
        );
    let graph = cache.graph(analysis_prepared);
    stage_durations.insert("graph".to_owned(), graph_started.elapsed().as_millis());

    progress.set_phase(format!(
        "Running rules… {} files",
        analysis_prepared.files.len()
    ));
    let rules_started = Instant::now();
    let family = if options.only.is_empty() {
        format!("command.{cache_command}")
    } else {
        format!("command.{cache_command}.only.{}", options.only)
    };
    let mut rule_family_durations = BTreeMap::new();
    let mut analysis_profile = AnalysisProfile::default();
    let mut findings = if let Some(findings) = cache.findings(analysis_prepared, &family) {
        findings
    } else {
        let context = SourceAnalysisContext::with_auxiliary(
            &analysis_prepared.sources,
            &base_sources,
            &changed_paths,
            options.changed_base.is_some(),
            &auxiliary,
        );
        let plan = ExecutionPlan::new(
            options,
            &analysis_prepared.config,
            analysis_prepared
                .files
                .iter()
                .map(|file| file.language.as_str()),
        );
        let output = analysis_engine::analyze(
            analysis_prepared,
            &context,
            &graph,
            &plan,
            options.verbose || options.profile,
        )?;
        cache.store_findings(analysis_prepared, &family, &output.findings);
        rule_family_durations = output.family_durations_milliseconds;
        analysis_profile = output.profile;
        output.findings
    };
    stage_durations.insert("rules".to_owned(), rules_started.elapsed().as_millis());

    progress.set_phase("Preparing report…");
    let sarif_started = Instant::now();
    let ingestion = sarif_ingestion::read(&options.ingest_sarif, Path::new(&prepared.root));
    findings.extend(ingestion.findings);
    stage_durations.insert(
        "sarifIngestion".to_owned(),
        sarif_started.elapsed().as_millis(),
    );
    if options.changed_base.is_some() {
        findings.retain(|finding| changed_paths.contains(&finding.path));
    }
    if prepared.config.changed_lines {
        findings.retain(|finding| {
            if prepared.changed_line_ranges.is_empty() {
                return true;
            }
            let end = finding.end_line.max(finding.line);
            prepared
                .changed_line_ranges
                .get(&finding.path)
                .is_some_and(|ranges| {
                    ranges
                        .iter()
                        .any(|range| finding.line <= range.end && end >= range.start)
                })
        });
    }
    let controls_started = Instant::now();
    let controlled = finding_controls::apply(
        findings,
        options,
        &analysis_prepared.config,
        &analysis_prepared.sources,
        taxonomy_group,
    )?;
    stage_durations.insert(
        "controls".to_owned(),
        controls_started.elapsed().as_millis(),
    );
    prepared.diagnostics.extend(ingestion.diagnostics);
    prepared.graph_cache_hit = cache.graph_hit;
    prepared.findings_cache_hit = cache.findings_hit;
    prepared.duration_milliseconds = started.elapsed().as_millis();
    prepared.stage_durations_milliseconds = stage_durations;
    prepared.rule_family_durations_milliseconds = rule_family_durations;
    prepared.analysis_profile = analysis_profile;
    progress.finish();
    Ok(AnalysisRun {
        prepared,
        findings: controlled.active,
        actionable_findings: controlled.actionable,
        actionable_count: controlled.actionable_count,
        advisory_summary: controlled.advisory_summary,
    })
}

pub fn execute(options: &PreviewOptions) -> Result<SummaryOutcome, String> {
    execute_report(options, "summary")
}

pub(crate) fn execute_report(
    options: &PreviewOptions,
    command: &'static str,
) -> Result<SummaryOutcome, String> {
    let run = analyze_for(options, command)?;
    if run.prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(SummaryOutcome::Empty);
    }
    let detailed = if options.all_findings || options.include_advisory {
        run.findings
    } else if !options.finding_group.is_empty() {
        run.findings
            .into_iter()
            .filter(|finding| taxonomy_group(&finding.code) == options.finding_group)
            .collect()
    } else {
        run.actionable_findings
    };
    let output = render(
        options.format.clone(),
        &FindingReport {
            command,
            prepared: &run.prepared,
            findings: &detailed,
            actionable_count: run.actionable_count,
            advisory_summary: &run.advisory_summary,
            show_advisory_hint: command == "summary"
                && !options.include_advisory
                && !options.all_findings,
            verbose: options.verbose,
            profile: options.profile,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && run.actionable_count > 0 {
        Ok(SummaryOutcome::Findings)
    } else {
        Ok(SummaryOutcome::Success)
    }
}

fn load_base_sources(
    root: &Path,
    base: Option<&str>,
    changed_paths: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let Some(base) = base else {
        return BTreeMap::new();
    };
    changed_paths
        .iter()
        .map(|path| (path.clone(), git_file(root, base, path).unwrap_or_default()))
        .collect()
}

fn git_file(root: &Path, revision: &str, path: &str) -> Option<String> {
    if revision.is_empty() || revision.starts_with('-') {
        return None;
    }
    let output = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["show", &format!("{revision}:{path}")])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn collect_auxiliary_files(metadata_files: &[RepositoryMetadataFile]) -> BTreeMap<String, String> {
    metadata_files
        .iter()
        .filter(|file| is_auxiliary_metadata_file(&file.relative))
        .map(|file| (file.relative.clone(), file.source.clone()))
        .collect()
}

fn is_auxiliary_metadata_file(relative: &str) -> bool {
    let path = Path::new(relative);
    let production_parent = path.parent().is_none_or(|parent| {
        parent.as_os_str().is_empty()
            || is_builtin_production_path(&parent.to_string_lossy().replace('\\', "/"))
    });
    if !production_parent {
        return false;
    }
    let name = path.file_name().and_then(|name| name.to_str());
    let named_auxiliary = name.is_some_and(|name| {
        [
            ".pre-commit-config.yaml",
            ".pre-commit-config.yml",
            "Cargo.lock",
            "Cargo.toml",
            "analysis_options.yaml",
            "l10n.yaml",
            "package.json",
            "pubspec.yaml",
            "pyproject.toml",
            "Makefile",
        ]
        .contains(&name)
    });
    named_auxiliary || is_ci_auxiliary_path(path)
}

fn is_ci_auxiliary_path(relative: &Path) -> bool {
    let file_name = relative.file_name().and_then(|name| name.to_str());
    let root_ci = relative.components().count() == 1
        && file_name.is_some_and(|name| {
            matches!(
                name,
                ".gitlab-ci.yml" | "azure-pipelines.yml" | "Jenkinsfile"
            )
        });
    let github_workflow = relative.parent() == Some(Path::new(".github/workflows"))
        && relative
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "yml" | "yaml"));
    root_ci || github_workflow
}

fn collect_flutter_asset_existence(
    root: &Path,
    sources: &BTreeMap<String, String>,
    auxiliary: &mut BTreeMap<String, String>,
) {
    for source in sources.values() {
        for capture in FLUTTER_ASSET_REFERENCE.captures_iter(source) {
            let Some(asset) = capture.get(1).map(|value| value.as_str()) else {
                continue;
            };
            auxiliary
                .entry(format!("@exists/{asset}"))
                .or_insert_with(|| root.join(asset).is_file().to_string());
        }
    }
}

static FLUTTER_ASSET_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:Image\.asset|AssetImage)\s*\(\s*["'](assets/[^"']+)["']"#).unwrap()
});

pub(crate) fn taxonomy_group(code: &str) -> &'static str {
    rule_catalog::descriptor(code)
        .map(|descriptor| descriptor.group)
        // Project-defined pattern rules are report-mode findings in the Dart contract.
        .unwrap_or("security")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_design_and_security_taxonomies_to_stable_groups() {
        assert_eq!(
            taxonomy_group("single-method-delegating-class"),
            "maintainability"
        );
        assert_eq!(taxonomy_group("tab-indent"), "style");
        assert_eq!(taxonomy_group("ai-model-output-to-execution"), "security");
    }

    #[test]
    fn uses_canonical_groups_for_aggregated_and_project_rules() {
        assert_eq!(taxonomy_group("dart-broad-catch"), "reliability");
        assert_eq!(taxonomy_group("project-defined-rule"), "security");
    }

    #[test]
    fn loads_manifests_locks_and_supported_ci_without_arbitrary_yaml() {
        let root = tempfile::tempdir().expect("temporary repository must be created");
        let member = root.path().join("member");
        let workflows = root.path().join(".github/workflows");
        fs::create_dir_all(&member).unwrap();
        fs::create_dir_all(&workflows).unwrap();
        fs::create_dir_all(root.path().join(".github/other")).unwrap();
        fs::write(root.path().join("package.json"), "{}").unwrap();
        fs::write(root.path().join("Cargo.lock"), "version = 4").unwrap();
        fs::write(root.path().join("Makefile"), "lint:\n\tcargo clippy").unwrap();
        fs::write(root.path().join(".pre-commit-config.yaml"), "repos: []").unwrap();
        fs::write(root.path().join(".gitlab-ci.yml"), "test: cargo test").unwrap();
        fs::write(
            root.path().join("azure-pipelines.yml"),
            "script: cargo test",
        )
        .unwrap();
        fs::write(root.path().join("Jenkinsfile"), "sh 'cargo test'").unwrap();
        fs::write(workflows.join("ci.yml"), "run: cargo test").unwrap();
        fs::write(workflows.join("audit.yaml"), "run: cargo audit").unwrap();
        fs::write(workflows.join("notes.txt"), "cargo test").unwrap();
        fs::write(root.path().join(".github/other/ci.yml"), "run: cargo test").unwrap();
        fs::write(root.path().join("random.yaml"), "run: cargo test").unwrap();
        fs::write(member.join(".gitlab-ci.yml"), "test: cargo test").unwrap();
        fs::write(member.join("Cargo.toml"), "[package]\nname='member'").unwrap();
        fs::write(member.join("Cargo.lock"), "version = 4").unwrap();
        fs::write(
            member.join("analysis_options.yaml"),
            "include: package:lints/recommended.yaml",
        )
        .unwrap();

        let files = auxiliary_files(root.path());

        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                ".github/workflows/audit.yaml",
                ".github/workflows/ci.yml",
                ".gitlab-ci.yml",
                ".pre-commit-config.yaml",
                "Cargo.lock",
                "Jenkinsfile",
                "Makefile",
                "azure-pipelines.yml",
                "member/Cargo.lock",
                "member/Cargo.toml",
                "member/analysis_options.yaml",
                "package.json",
            ]
        );
    }

    #[test]
    fn skips_test_manifests_and_tolerates_malformed_production_metadata() {
        let root = tempfile::tempdir().expect("temporary repository must be created");
        let member = root.path().join("member");
        let tests = root.path().join("tests/registry");
        let tests_common = root.path().join("devel-common/src/tests_common");
        fs::create_dir_all(&member).unwrap();
        fs::create_dir_all(&tests).unwrap();
        fs::create_dir_all(&tests_common).unwrap();
        fs::write(member.join("package.json"), [0xff, b'{']).unwrap();
        fs::write(tests.join("package.json"), [0xff]).unwrap();
        fs::write(tests_common.join("package.json"), [0xff]).unwrap();

        let files = auxiliary_files(root.path());

        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["member/package.json"]
        );
        assert_eq!(files["member/package.json"], "\u{fffd}{");
    }

    fn auxiliary_files(root: &Path) -> BTreeMap<String, String> {
        let inspection =
            crate::repository_defaults::RepositoryDefaults::inspect(root, true, true, true);
        collect_auxiliary_files(&inspection.metadata_files)
    }
}
