use std::path::Path;

use crate::analysis_cache::AnalysisCache;
use crate::cli::PreviewOptions;
use crate::dead_analysis;
use crate::discovery::prepare;
use crate::export_analysis;
use crate::finding_controls;
use crate::report::{FindingReport, render};
use crate::sarif_ingestion;

pub enum DeadOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<DeadOutcome, String> {
    let mut prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(DeadOutcome::Empty);
    }
    let mut cache = AnalysisCache::new(options, Path::new(&prepared.root));
    let graph = cache.graph(&prepared);
    let mut findings =
        if let Some(findings) = cache.findings(&prepared, &prepared.sources, "command.dead") {
            findings
        } else {
            let mut findings = dead_analysis::analyze(&prepared, &graph);
            findings.extend(export_analysis::analyze(
                Path::new(&prepared.root),
                &prepared.sources,
            ));
            cache.store_findings(&prepared, &prepared.sources, "command.dead", &findings);
            findings
        };
    prepared.graph_cache_hit = cache.graph_hit;
    prepared.findings_cache_hit = cache.findings_hit;
    let ingestion = sarif_ingestion::read(&options.ingest_sarif, Path::new(&prepared.root));
    findings.extend(ingestion.findings);
    prepared.diagnostics.extend(ingestion.diagnostics);
    let controlled = finding_controls::apply(
        findings,
        options,
        &prepared.config,
        &prepared.sources,
        dead_group,
    )?;
    let (detailed, actionable_count, advisory_summary) =
        finding_controls::detailed(controlled, options, dead_group);
    let output = render(
        options.format.clone(),
        &FindingReport {
            command: "dead",
            prepared: &prepared,
            findings: &detailed,
            actionable_count,
            advisory_summary: &advisory_summary,
            verbose: options.verbose,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && actionable_count > 0 {
        Ok(DeadOutcome::Findings)
    } else {
        Ok(DeadOutcome::Success)
    }
}

fn dead_group(code: &str) -> &'static str {
    if code.starts_with("architecture-") {
        "architecture"
    } else if code.starts_with("mvvm-") {
        "maintainability"
    } else {
        "correctness"
    }
}
