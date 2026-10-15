use std::path::Path;

use crate::analysis_cache::AnalysisCache;
use crate::cli::PreviewOptions;
use crate::discovery::prepare;
use crate::finding_controls;
use crate::report::{FindingReport, render};
use crate::sarif_ingestion;
use crate::structure;

pub enum StructureOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<StructureOutcome, String> {
    let mut prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(StructureOutcome::Empty);
    }
    let mut cache = AnalysisCache::new(options, Path::new(&prepared.root));
    let mut findings =
        if let Some(findings) = cache.findings(&prepared, &prepared.sources, "command.structure") {
            findings
        } else {
            let findings = structure::analyze(&prepared.files, &prepared.config);
            cache.store_findings(&prepared, &prepared.sources, "command.structure", &findings);
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
        structure_group,
    )?;
    let (detailed, actionable_count, advisory_summary) =
        finding_controls::detailed(controlled, options, structure_group);
    let output = render(
        options.format.clone(),
        &FindingReport {
            command: "structure",
            prepared: &prepared,
            findings: &detailed,
            actionable_count,
            advisory_summary: &advisory_summary,
            verbose: options.verbose,
        },
    )?;
    println!("{output}");
    if options.fail_on_issues && actionable_count > 0 {
        Ok(StructureOutcome::Findings)
    } else {
        Ok(StructureOutcome::Success)
    }
}

fn structure_group(_: &str) -> &'static str {
    "correctness"
}
