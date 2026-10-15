use std::path::Path;

use crate::analysis_cache::AnalysisCache;
use crate::cli::PreviewOptions;
use crate::discovery::prepare;
use crate::feature_flags;
use crate::finding_controls;
use crate::report::{FindingReport, render};
use crate::sarif_ingestion;

pub enum FlagsOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<FlagsOutcome, String> {
    let mut prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(FlagsOutcome::Empty);
    }
    let mut cache = AnalysisCache::new(options, Path::new(&prepared.root));
    let mut findings =
        if let Some(findings) = cache.findings(&prepared, &prepared.sources, "command.flags") {
            findings
        } else {
            let findings = feature_flags::analyze(&prepared.sources);
            cache.store_findings(&prepared, &prepared.sources, "command.flags", &findings);
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
        flags_group,
    )?;
    let (detailed, actionable_count, advisory_summary) =
        finding_controls::detailed(controlled, options, flags_group);
    let output = render(
        options.format.clone(),
        &FindingReport {
            command: "flags",
            prepared: &prepared,
            findings: &detailed,
            actionable_count,
            advisory_summary: &advisory_summary,
            verbose: options.verbose,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && actionable_count > 0 {
        Ok(FlagsOutcome::Findings)
    } else {
        Ok(FlagsOutcome::Success)
    }
}

fn flags_group(_: &str) -> &'static str {
    "maintainability"
}
