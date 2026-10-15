use std::path::Path;

use crate::analysis_cache::AnalysisCache;
use crate::cli::PreviewOptions;
use crate::complexity;
use crate::discovery::prepare;
use crate::finding_controls;
use crate::function_sources;
use crate::report::{FindingReport, render};
use crate::sarif_ingestion;

pub enum ComplexityOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<ComplexityOutcome, String> {
    let mut prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(ComplexityOutcome::Empty);
    }
    let mut cache = AnalysisCache::new(options, Path::new(&prepared.root));
    let mut findings = if let Some(findings) = cache.findings(&prepared, "command.complexity") {
        findings
    } else {
        let functions = function_sources::extract(&prepared.sources);
        let findings = complexity::analyze(&functions, &prepared.sources, &prepared.config);
        cache.store_findings(&prepared, "command.complexity", &findings);
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
        complexity_group,
    )?;
    let (detailed, actionable_count, advisory_summary) =
        finding_controls::detailed(controlled, options, complexity_group);
    let output = render(
        options.format.clone(),
        &FindingReport {
            command: "complexity",
            prepared: &prepared,
            findings: &detailed,
            actionable_count,
            advisory_summary: &advisory_summary,
            verbose: options.verbose,
            profile: options.profile,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && actionable_count > 0 {
        Ok(ComplexityOutcome::Findings)
    } else {
        Ok(ComplexityOutcome::Success)
    }
}

fn complexity_group(code: &str) -> &'static str {
    if code == "complex-function" {
        "maintainability"
    } else {
        "correctness"
    }
}
