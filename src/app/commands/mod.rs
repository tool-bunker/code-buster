use std::collections::BTreeMap;

use crate::cli::PreviewOptions;
use crate::discovery::PreparedPreview;
use crate::findings::Finding;
use crate::report::{FindingReport, render};

pub(crate) mod baseline;
pub(crate) mod completions;
pub(crate) mod complexity;
pub(crate) mod config;
pub(crate) mod dead;
pub(crate) mod doctor;
pub(crate) mod duplication;
pub(crate) mod explain;
pub(crate) mod fix;
pub(crate) mod graph;
pub(crate) mod hotspots;
pub(crate) mod init;
pub(crate) mod quality;
pub(crate) mod repository_view;
pub(crate) mod rules;
pub(crate) mod structure;
pub(crate) mod summary;
pub(crate) mod update;

fn print_quality_report(
    options: &PreviewOptions,
    prepared: &PreparedPreview,
    findings: &[Finding],
    actionable_count: usize,
    advisory_summary: &BTreeMap<String, usize>,
) -> Result<(), String> {
    println!(
        "{}",
        render(
            options.format.clone(),
            &FindingReport {
                command: "quality",
                prepared,
                findings,
                actionable_count,
                advisory_summary,
                show_advisory_hint: false,
                verbose: options.verbose,
                profile: options.profile,
            },
        )?
    );
    Ok(())
}
pub(crate) mod workflow;
