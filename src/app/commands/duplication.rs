use std::path::Path;

use crate::advanced_duplication;
use crate::analysis_cache::AnalysisCache;
use crate::cli::PreviewOptions;
use crate::dart_model_duplication;
use crate::discovery::prepare;
use crate::duplication;
use crate::finding_controls;
use crate::function_sources;
use crate::report::{FindingReport, render};
use crate::sarif_ingestion;

pub enum DuplicationOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<DuplicationOutcome, String> {
    execute_named(options, "duplication")
}

pub fn execute_clusters(options: &PreviewOptions) -> Result<DuplicationOutcome, String> {
    execute_named(options, "clusters")
}

fn execute_named(
    options: &PreviewOptions,
    command: &'static str,
) -> Result<DuplicationOutcome, String> {
    let mut prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(DuplicationOutcome::Empty);
    }
    let mode = prepared.config.duplication_mode.as_str();
    if !matches!(mode, "exact" | "normalized" | "semantic") {
        return Err(format!("unsupported duplication mode: {mode}"));
    }
    let mut cache = AnalysisCache::new(options, Path::new(&prepared.root));
    let family = format!("command.{command}");
    let mut findings = if let Some(findings) = cache.findings(&prepared, &prepared.sources, &family)
    {
        findings
    } else {
        let mut findings =
            duplication::exact_findings(&prepared.sources, prepared.config.min_duplication_lines);
        if mode != "exact" {
            let functions = function_sources::extract(&prepared.sources);
            findings.extend(advanced_duplication::near_duplicate_functions(&functions));
            if mode == "semantic" {
                findings.extend(advanced_duplication::parallel_contract_implementations(
                    &functions,
                ));
            }
        }
        findings.extend(duplication::repeated_condition_findings(&prepared.sources));
        if mode == "semantic" {
            findings.extend(dart_model_duplication::overlapping_models(
                &prepared.sources,
            ));
        }
        cache.store_findings(&prepared, &prepared.sources, &family, &findings);
        findings
    };
    prepared.findings_cache_hit = cache.findings_hit;
    let ingestion = sarif_ingestion::read(&options.ingest_sarif, Path::new(&prepared.root));
    findings.extend(ingestion.findings);
    prepared.diagnostics.extend(ingestion.diagnostics);
    let controlled = finding_controls::apply(
        findings,
        options,
        &prepared.config,
        &prepared.sources,
        duplication_group,
    )?;
    let (detailed, actionable_count, advisory_summary) =
        finding_controls::detailed(controlled, options, duplication_group);
    let output = render(
        options.format.clone(),
        &FindingReport {
            command,
            prepared: &prepared,
            findings: &detailed,
            actionable_count,
            advisory_summary: &advisory_summary,
            verbose: options.verbose,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && actionable_count > 0 {
        Ok(DuplicationOutcome::Findings)
    } else {
        Ok(DuplicationOutcome::Success)
    }
}

fn duplication_group(code: &str) -> &'static str {
    if code == "near-duplicate-function" {
        "correctness"
    } else {
        "maintainability"
    }
}
