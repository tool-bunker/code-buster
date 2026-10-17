use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Write as _};
use std::process::Command;

use super::terminal;
use crate::cli::ReportFormat;
use crate::config::{Config, PatternRule};
use crate::discovery::{AnalysisProfile, PreparedPreview, ProcessingDiagnostic, RulePackTiming};
use crate::findings::{Finding, Severity, rule_suggestion, rule_why};
use crate::rule_catalog;

pub struct FindingReport<'a> {
    pub command: &'static str,
    pub prepared: &'a PreparedPreview,
    pub findings: &'a [Finding],
    pub actionable_count: usize,
    pub advisory_summary: &'a BTreeMap<String, usize>,
    pub show_advisory_hint: bool,
    pub verbose: bool,
    pub profile: bool,
}

pub fn render(format: ReportFormat, report: &FindingReport<'_>) -> Result<String, String> {
    match format {
        ReportFormat::Text => Ok(text(report, terminal::colors_enabled())),
        ReportFormat::Json => serde_json::to_string(&json_envelope(report))
            .map_err(|error| format!("failed to encode finding report: {error}")),
        ReportFormat::Ndjson => ndjson(report),
        ReportFormat::Markdown => Ok(markdown(report)),
        ReportFormat::Sarif => serde_json::to_string(&sarif(report.findings))
            .map_err(|error| format!("failed to encode SARIF report: {error}")),
        ReportFormat::Junit => Ok(junit(report.findings)),
        ReportFormat::Mermaid => {
            Err("Mermaid output is only supported by graph commands".to_owned())
        }
    }
}

fn text(report: &FindingReport<'_>, color: bool) -> String {
    let title = if report.command == "clusters" {
        "summary"
    } else {
        report.command
    };
    let palette = TerminalPalette::new(color);
    let mut output = String::new();
    let clean = report.actionable_count == 0;
    palette.write(
        &mut output,
        if clean { "1;32" } else { "1;31" },
        if clean { "✓" } else { "✗" },
    );
    output.push(' ');
    palette.write(&mut output, "1;36", "Code Buster");
    if title != "summary" {
        let _ = write!(output, " {title}");
    }
    output.push_str(" — ");
    if clean {
        palette.write(&mut output, "32", "no actionable findings");
    } else {
        palette.write(
            &mut output,
            "1;31",
            format_args!(
                "{} actionable finding{}",
                report.actionable_count,
                if report.actionable_count == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        );
    }

    write_text_statistics(&mut output, report, palette);
    write_text_language_summary(&mut output, report, palette);
    write_text_diagnostics(&mut output, report, palette);
    write_text_advisory_summary(&mut output, report, palette);
    write_text_findings(&mut output, report, palette);
    write_text_next_step(&mut output, report, palette);
    output
}

fn write_text_diagnostics(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    if report.verbose {
        write_text_scope(output, report, palette);
    }
    if report.verbose || report.profile {
        write_text_performance(output, report, palette);
    }
    if report.profile {
        write_text_rule_profile(output, report, palette);
    }
}

fn write_text_statistics(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    output.push('\n');
    write_statistic(
        output,
        palette,
        "Files",
        format_args!("{} analyzed", report.prepared.files.len()),
        "",
    );
    if report.findings.len() == report.actionable_count {
        for (label, severity, style) in [
            ("Errors", Severity::Error, "1;31"),
            ("Warnings", Severity::Warn, "33"),
            ("Info", Severity::Info, "1;36"),
        ] {
            let count = report
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .count();
            if count > 0 {
                write_statistic(output, palette, label, count, style);
            }
        }
    } else if report.actionable_count > 0 {
        write_statistic(
            output,
            palette,
            "Actionable",
            report.actionable_count,
            "1;31",
        );
    }
    let advisory_count = advisory_count(report);
    if advisory_count > 0 {
        write_statistic(output, palette, "Advisory", advisory_count, "33");
    }
    if report.prepared.duration_milliseconds > 0 {
        write_statistic(
            output,
            palette,
            "Time",
            formatted_duration(report.prepared.duration_milliseconds),
            "",
        );
    }
    if report.prepared.duration_milliseconds > 0
        || report.prepared.graph_cache_hit
        || report.prepared.findings_cache_hit
    {
        write_statistic(output, palette, "Cache", cache_status(report), "");
    }
}

fn write_statistic(
    output: &mut String,
    palette: TerminalPalette,
    label: &str,
    value: impl Display,
    value_style: &str,
) {
    output.push_str("\n  ");
    palette.write(output, "2", format_args!("{label:<12}"));
    palette.write(output, value_style, value);
}

fn formatted_duration(milliseconds: u128) -> String {
    if milliseconds < 1_000 {
        format!("{milliseconds}ms")
    } else {
        format!("{:.1}s", milliseconds as f64 / 1_000.0)
    }
}

fn cache_status(report: &FindingReport<'_>) -> &'static str {
    match (
        report.prepared.graph_cache_hit,
        report.prepared.findings_cache_hit,
    ) {
        (true, true) => "hit",
        (true, false) | (false, true) => "partial",
        (false, false) => "miss",
    }
}

fn write_text_language_summary(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    let summary = language_summary(report);
    if summary.len() <= 1 {
        return;
    }
    output.push_str("\n\n");
    palette.write(output, "1", "Languages");
    for (language, (files, findings)) in summary {
        output.push_str("\n  ");
        palette.write(output, "2", format_args!("{language:<14}"));
        let _ = write!(
            output,
            "{files:>4} file{}  {findings:>4} finding{}",
            if files == 1 { "" } else { "s" },
            if findings == 1 { "" } else { "s" }
        );
    }
}

fn write_text_scope(output: &mut String, report: &FindingReport<'_>, palette: TerminalPalette) {
    if report.prepared.coverage.is_empty() {
        return;
    }
    output.push_str("\n\n");
    palette.write(output, "1", "Scope");
    for (key, value) in &report.prepared.coverage {
        output.push_str("\n  ");
        palette.write(output, "2", format_args!("{key:<18}"));
        let _ = write!(output, "{value}");
    }
}

fn write_text_performance(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    if report.prepared.stage_durations_milliseconds.is_empty() {
        return;
    }
    output.push_str("\n\n");
    palette.write(output, "1", "Performance");
    for (stage, duration) in &report.prepared.stage_durations_milliseconds {
        output.push_str("\n  ");
        palette.write(output, "2", format_args!("{stage:<18}"));
        output.push_str(&formatted_duration(*duration));
    }
}

fn write_text_rule_profile(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    let profile = &report.prepared.analysis_profile;
    if profile.rule_packs.is_empty() {
        return;
    }
    let pack_total = profile
        .rule_packs
        .iter()
        .map(|timing| timing.duration_microseconds)
        .sum();
    output.push_str("\n\n");
    palette.write(output, "1", "Rule profile");
    write_profile_total(output, palette, "Pack execution", pack_total);
    for timing in sorted_pack_timings(profile) {
        write_profile_entry(
            output,
            palette,
            &timing.id,
            timing.duration_microseconds,
            pack_total,
            Some(&timing.family),
        );
    }
    write_profile_group(
        output,
        palette,
        "Shared analysis",
        &profile.shared_durations_microseconds,
    );
    write_profile_group(
        output,
        palette,
        "Individual rule checks",
        &profile.rule_durations_microseconds,
    );
}

fn write_profile_group(
    output: &mut String,
    palette: TerminalPalette,
    title: &str,
    durations: &BTreeMap<String, u128>,
) {
    if durations.is_empty() {
        return;
    }
    let total = durations.values().sum();
    output.push_str("\n\n");
    palette.write(output, "1", title);
    write_profile_total(output, palette, "Measured total", total);
    for (name, duration) in sorted_durations(durations) {
        write_profile_entry(output, palette, name, duration, total, None);
    }
}

fn write_profile_total(
    output: &mut String,
    palette: TerminalPalette,
    label: &str,
    duration_microseconds: u128,
) {
    output.push_str("\n  ");
    palette.write(output, "2", format_args!("{label:<26}"));
    output.push_str(&formatted_profile_duration(duration_microseconds));
}

fn write_profile_entry(
    output: &mut String,
    palette: TerminalPalette,
    name: &str,
    duration_microseconds: u128,
    total_microseconds: u128,
    family: Option<&str>,
) {
    output.push_str("\n  ");
    palette.write(output, "2", format_args!("{name:<26}"));
    let _ = write!(
        output,
        "{:>9}  {:>5.1}%",
        formatted_profile_duration(duration_microseconds),
        percentage(duration_microseconds, total_microseconds)
    );
    if let Some(family) = family
        && family != name
    {
        let _ = write!(output, "  {family}");
    }
}

fn sorted_pack_timings(profile: &AnalysisProfile) -> Vec<&RulePackTiming> {
    let mut timings = profile.rule_packs.iter().collect::<Vec<_>>();
    timings.sort_by(|left, right| {
        right
            .duration_microseconds
            .cmp(&left.duration_microseconds)
            .then_with(|| left.id.cmp(&right.id))
    });
    timings
}

fn sorted_durations(durations: &BTreeMap<String, u128>) -> Vec<(&str, u128)> {
    let mut timings = durations
        .iter()
        .map(|(name, duration)| (name.as_str(), *duration))
        .collect::<Vec<_>>();
    timings.sort_by(|(left_name, left_duration), (right_name, right_duration)| {
        right_duration
            .cmp(left_duration)
            .then_with(|| left_name.cmp(right_name))
    });
    timings
}

fn formatted_profile_duration(microseconds: u128) -> String {
    if microseconds < 1_000 {
        format!("{microseconds}µs")
    } else if microseconds < 1_000_000 {
        format!("{:.1}ms", microseconds as f64 / 1_000.0)
    } else {
        format!("{:.2}s", microseconds as f64 / 1_000_000.0)
    }
}

fn percentage(duration: u128, total: u128) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (duration as f64 * 1_000.0 / total as f64).round() / 10.0
}

fn write_text_advisory_summary(
    output: &mut String,
    report: &FindingReport<'_>,
    palette: TerminalPalette,
) {
    if report.advisory_summary.is_empty() {
        return;
    }
    output.push_str("\n\n");
    palette.write(output, "1", "Advisory breakdown");
    if report.show_advisory_hint {
        output.push(' ');
        palette.write(output, "2;90", "(cb --advisory)");
    }
    for (group, count) in report.advisory_summary {
        output.push_str("\n  ");
        palette.write(output, "35", format_args!("{group:<18}"));
        let _ = write!(output, "{count}");
    }
}

fn advisory_count(report: &FindingReport<'_>) -> usize {
    report.advisory_summary.values().sum()
}

fn write_text_findings(output: &mut String, report: &FindingReport<'_>, palette: TerminalPalette) {
    if report.findings.is_empty() {
        return;
    }
    output.push_str("\n\n");
    palette.write(output, "1", "Findings");
    for finding in report.findings {
        write_text_finding(output, finding, palette);
        if report.verbose {
            write_text_finding_details(output, finding, palette);
        }
    }
}

fn write_text_finding(output: &mut String, finding: &Finding, palette: TerminalPalette) {
    let (severity, severity_style) = match finding.severity {
        Severity::Error => ("ERROR", "1;31"),
        Severity::Warn => ("WARN", "33"),
        Severity::Info => ("INFO", "1;36"),
    };
    output.push_str("\n\n  ");
    palette.write(output, severity_style, format_args!("{severity:<6}"));
    palette.write(output, "1;36", &finding.code);
    output.push_str("\n        ");
    if finding.end_line > finding.line {
        palette.write(
            output,
            "2",
            format_args!("{}:{}-{}", finding.path, finding.line, finding.end_line),
        );
    } else {
        palette.write(
            output,
            "2",
            format_args!("{}:{}", finding.path, finding.line),
        );
    }
    write_text_finding_message(output, finding, palette);
}

fn write_text_finding_message(output: &mut String, finding: &Finding, palette: TerminalPalette) {
    output.push_str("\n        ");
    let Some((name, cyclomatic, cognitive)) = complexity_metrics(finding) else {
        output.push_str(&finding.message);
        return;
    };
    output.push_str(name);
    output.push_str("\n        ");
    palette.write(output, "2", "Cyclomatic");
    output.push_str("  ");
    palette.write(output, "1;33", cyclomatic);
    output.push_str("  ·  ");
    palette.write(output, "2", "Cognitive");
    output.push_str("  ");
    palette.write(output, "1;33", cognitive);
}

fn complexity_metrics(finding: &Finding) -> Option<(&str, &str, &str)> {
    if finding.code != "complex-function" {
        return None;
    }
    let (prefix, cognitive) = finding.message.rsplit_once(" cognitive=")?;
    let (name, cyclomatic) = prefix.rsplit_once(" complexity=")?;
    if name.is_empty()
        || cyclomatic.parse::<usize>().is_err()
        || cognitive.parse::<usize>().is_err()
    {
        return None;
    }
    Some((name, cyclomatic, cognitive))
}

fn write_text_finding_details(output: &mut String, finding: &Finding, palette: TerminalPalette) {
    if !finding.why.is_empty() {
        output.push_str("\n        ");
        palette.write(output, "2", "Why:");
        let _ = write!(output, " {}", finding.why);
    }
    if !finding.confidence.is_empty() {
        output.push_str("\n        ");
        palette.write(output, "2", "Confidence:");
        let _ = write!(output, " {}", finding.confidence);
    }
    if !finding.related_files.is_empty() {
        output.push_str("\n        ");
        palette.write(output, "2", "Related:");
        output.push(' ');
        for (index, related_file) in finding.related_files.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(related_file);
        }
    }
    if !finding.suggestion.is_empty() {
        output.push_str("\n        ");
        palette.write(output, "2", "Suggestion:");
        let _ = write!(output, " {}", finding.suggestion);
    }
}

fn write_text_next_step(output: &mut String, report: &FindingReport<'_>, palette: TerminalPalette) {
    let next = if report.actionable_count > 0 {
        Some("Review actionable findings: cb review --verbose")
    } else if advisory_count(report) > 0 {
        Some("Review advisory findings: cb review --advisory")
    } else {
        None
    };
    if let Some(next) = next {
        output.push_str("\n\n  ");
        palette.write(output, "1;36", "→");
        let _ = write!(output, " {next}");
    }
}

#[derive(Clone, Copy)]
struct TerminalPalette {
    enabled: bool,
}

impl TerminalPalette {
    const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn write(self, output: &mut String, code: &str, value: impl Display) {
        if self.enabled && !code.is_empty() {
            let _ = write!(output, "\u{1b}[{code}m{value}\u{1b}[0m");
        } else {
            let _ = write!(output, "{value}");
        }
    }
}

fn json_envelope(report: &FindingReport<'_>) -> Value {
    let mut object = Map::new();
    object.insert("schemaVersion".to_owned(), json!(3));
    object.insert("version".to_owned(), json!(1));
    object.insert("command".to_owned(), json!(report.command));
    object.insert("root".to_owned(), json!(report.prepared.root));
    object.insert("files".to_owned(), json!(report.prepared.files.len()));
    let languages = language_summary(report)
        .into_iter()
        .map(|(language, (files, findings))| {
            json!({"language": language, "files": files, "findings": findings})
        })
        .collect::<Vec<_>>();
    if !languages.is_empty() {
        object.insert("languages".to_owned(), Value::Array(languages));
    }
    if !report.prepared.coverage.is_empty() {
        object.insert("coverage".to_owned(), json!(report.prepared.coverage));
    }
    object.insert(
        "actionableFindingCount".to_owned(),
        json!(report.actionable_count),
    );
    object.insert(
        "detailedFindingCount".to_owned(),
        json!(report.findings.len()),
    );
    object.insert(
        "advisorySummary".to_owned(),
        json!({
            "total": report.advisory_summary.values().sum::<usize>(),
            "groups": report.advisory_summary,
        }),
    );
    if !report.prepared.diagnostics.is_empty() {
        object.insert(
            "processingDiagnostics".to_owned(),
            json!(report.prepared.diagnostics),
        );
    }
    object.insert("manifest".to_owned(), manifest(report));
    object.insert(
        "findings".to_owned(),
        Value::Array(report.findings.iter().map(Finding::to_json).collect()),
    );
    Value::Object(object)
}

fn ndjson(report: &FindingReport<'_>) -> Result<String, String> {
    let mut records = vec![json!({
        "schemaVersion": 3,
        "recordType": "summary",
        "command": report.command,
        "root": report.prepared.root,
        "files": report.prepared.files.len(),
        "actionableFindingCount": report.actionable_count,
        "detailedFindingCount": report.findings.len(),
        "advisorySummary": {
            "total": report.advisory_summary.values().sum::<usize>(),
            "groups": report.advisory_summary,
        },
    })];
    for finding in report.findings {
        let Value::Object(mut object) = finding.to_json() else {
            return Err(
                "failed to encode NDJSON report: finding JSON must be an object".to_owned(),
            );
        };
        object.insert("schemaVersion".to_owned(), json!(3));
        object.insert("recordType".to_owned(), json!("finding"));
        records.push(Value::Object(object));
    }
    records.extend(
        report
            .prepared
            .diagnostics
            .iter()
            .map(processing_diagnostic_record),
    );
    records
        .into_iter()
        .map(|record| {
            serde_json::to_string(&record)
                .map_err(|error| format!("failed to encode NDJSON report: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
}

fn processing_diagnostic_record(diagnostic: &ProcessingDiagnostic) -> Value {
    json!({
        "schemaVersion": 3,
        "recordType": "processingDiagnostic",
        "code": diagnostic.code,
        "severity": diagnostic.severity,
        "stage": diagnostic.stage,
        "path": diagnostic.path,
        "message": diagnostic.message,
    })
}

fn markdown(report: &FindingReport<'_>) -> String {
    let mut output = format!(
        "# Code Buster Nim {}\n\n- root: `{}`\n- files: {}\n- findings: {}\n",
        report.command,
        report.prepared.root,
        report.prepared.files.len(),
        report.findings.len()
    );
    if report.findings.is_empty() {
        return output.trim_end().to_owned();
    }
    output.push_str("\n| severity | code | location | message |\n|---|---|---|---|\n");
    for finding in report.findings {
        let location = if finding.end_line > finding.line {
            format!("{}:{}-{}", finding.path, finding.line, finding.end_line)
        } else {
            format!("{}:{}", finding.path, finding.line)
        };
        output.push_str(&format!(
            "| {} | `{}` | `{location}` | {} |\n",
            finding.severity.as_str(),
            finding.code,
            finding.message.replace('|', "\\|")
        ));
    }
    output.trim_end().to_owned()
}

fn sarif(findings: &[Finding]) -> Value {
    let mut seen = BTreeSet::new();
    let rules = findings
        .iter()
        .filter(|finding| seen.insert(finding.code.as_str()))
        .map(|finding| {
            let code = finding.code.as_str();
            json!({
                "id": code,
                "name": code,
                "shortDescription": {"text": code},
                "fullDescription": {"text": rule_why(code)},
                "help": {"text": rule_suggestion(code)},
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.code,
                "level": match finding.severity {
                    Severity::Error => "error",
                    Severity::Warn => "warning",
                    Severity::Info => "note",
                },
                "message": {"text": finding.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path},
                        "region": {"startLine": finding.line, "endLine": finding.end_line},
                    }
                }],
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "properties": {"codeBusterReportSchemaVersion": 3},
            "tool": {"driver": {
                "name": "code-buster",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

fn junit(findings: &[Finding]) -> String {
    let mut output = format!(
        "<testsuite name=\"code-buster\" tests=\"{}\" failures=\"{}\">",
        findings.len(),
        findings.len()
    );
    for finding in findings {
        let location = if finding.end_line > finding.line {
            format!("{}:{}-{}", finding.path, finding.line, finding.end_line)
        } else {
            format!("{}:{}", finding.path, finding.line)
        };
        output.push_str(&format!(
            "\n<testcase classname=\"{}\" name=\"{}\">",
            xml(&finding.path),
            xml(&finding.code)
        ));
        output.push_str(&format!(
            "\n<failure message=\"{}\">{} {}</failure>\n</testcase>",
            xml(&finding.message),
            finding.severity.as_str(),
            xml(&format!("{location} {}", finding.message))
        ));
    }
    output.push_str("\n</testsuite>");
    output
}

fn language_summary(report: &FindingReport<'_>) -> BTreeMap<String, (usize, usize)> {
    let mut summary = BTreeMap::new();
    let language_by_path: BTreeMap<&str, &str> = report
        .prepared
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.language.as_str()))
        .collect();
    for file in &report.prepared.files {
        summary
            .entry(file.language.clone())
            .or_insert((0usize, 0usize))
            .0 += 1;
    }
    for finding in report.findings {
        if let Some(language) = language_by_path.get(finding.path.as_str()) {
            summary.entry((*language).to_owned()).or_insert((0, 0)).1 += 1;
        }
    }
    summary
}

pub(crate) fn manifest(report: &FindingReport<'_>) -> Value {
    let selected_files: Vec<&str> = report
        .prepared
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let languages: BTreeSet<&str> = report
        .prepared
        .files
        .iter()
        .map(|file| file.language.as_str())
        .collect();
    let mut object = Map::new();
    object.insert("schemaVersion".to_owned(), json!(1));
    object.insert(
        "status".to_owned(),
        json!(if report.prepared.diagnostics.is_empty() {
            "complete"
        } else {
            "partial"
        }),
    );
    object.insert("command".to_owned(), json!(report.command));
    object.insert("root".to_owned(), json!(report.prepared.root));
    if let Some(revision) = git_revision(&report.prepared.root) {
        object.insert("gitRevision".to_owned(), json!(revision));
    }
    object.insert("sourceHash".to_owned(), json!(source_hash(report.prepared)));
    object.insert(
        "configHash".to_owned(),
        json!(config_hash(&report.prepared.config)),
    );
    object.insert("selectedFileCount".to_owned(), json!(selected_files.len()));
    if report.verbose {
        object.insert("selectedFiles".to_owned(), json!(selected_files));
    }
    object.insert("coverage".to_owned(), json!(report.prepared.coverage));
    object.insert("languages".to_owned(), json!(languages));
    if !report.prepared.language_versions.is_empty() {
        object.insert(
            "languageVersions".to_owned(),
            json!(report.prepared.language_versions),
        );
    }
    if report.verbose || report.profile {
        object.insert(
            "cache".to_owned(),
            json!({
                "graphHit": report.prepared.graph_cache_hit,
                "findingsHit": report.prepared.findings_cache_hit
            }),
        );
        object.insert(
            "durationMilliseconds".to_owned(),
            json!(report.prepared.duration_milliseconds),
        );
        object.insert(
            "stageDurationsMilliseconds".to_owned(),
            json!(report.prepared.stage_durations_milliseconds),
        );
        object.insert(
            "ruleFamilyDurationsMilliseconds".to_owned(),
            json!(report.prepared.rule_family_durations_milliseconds),
        );
    }
    if report.profile {
        object.insert(
            "profile".to_owned(),
            profile_json(&report.prepared.analysis_profile),
        );
    }
    Value::Object(object)
}

fn profile_json(profile: &AnalysisProfile) -> Value {
    let pack_total = profile
        .rule_packs
        .iter()
        .map(|timing| timing.duration_microseconds)
        .sum();
    let shared_total = profile.shared_durations_microseconds.values().sum();
    let rule_total = profile.rule_durations_microseconds.values().sum();
    json!({
        "cacheBypassed": true,
        "measurementUnit": "microseconds",
        "rulePackTotalMicroseconds": pack_total,
        "rulePacks": sorted_pack_timings(profile)
            .into_iter()
            .map(|timing| json!({
                "id": timing.id,
                "family": timing.family,
                "durationMicroseconds": timing.duration_microseconds,
                "percentageOfPackTime": percentage(timing.duration_microseconds, pack_total),
            }))
            .collect::<Vec<_>>(),
        "sharedAnalysisTotalMicroseconds": shared_total,
        "sharedAnalysis": json_profile_durations(
            &profile.shared_durations_microseconds,
            shared_total,
        ),
        "individualRuleTotalMicroseconds": rule_total,
        "individualRules": json_profile_durations(
            &profile.rule_durations_microseconds,
            rule_total,
        ),
    })
}

fn json_profile_durations(durations: &BTreeMap<String, u128>, total: u128) -> Vec<Value> {
    sorted_durations(durations)
        .into_iter()
        .map(|(name, duration)| {
            json!({
                "name": name,
                "durationMicroseconds": duration,
                "percentage": percentage(duration, total),
            })
        })
        .collect()
}

fn source_hash(prepared: &PreparedPreview) -> String {
    let mut material = String::new();
    for (path, source) in &prepared.sources {
        material.push_str(path);
        material.push('\n');
        let _ = writeln!(material, "{:x}", Sha256::digest(source.as_bytes()));
    }
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

fn config_hash(config: &Config) -> String {
    format!(
        "{:x}",
        Sha256::digest(cache_material(config, "manifest-config").as_bytes())
    )
}

pub(crate) fn cache_material(config: &Config, kind: &str) -> String {
    let mut material = String::new();
    for line in [
        "code-buster-cache-v5".to_owned(),
        rule_version_signature(),
        kind.to_owned(),
        config.language.clone(),
        config.languages.join(","),
        dart_list(config.frameworks.iter()),
        dart_list(config.includes.iter()),
        dart_list(config.excludes.iter()),
        config.changed_base.clone().unwrap_or_default(),
        config.changed_lines.to_string(),
        dart_list(config.entry_points.iter()),
        dart_list(config.ignore_patterns.iter()),
        dart_list(config.classification_production.iter()),
        dart_list(config.classification_test.iter()),
        dart_list(config.classification_generated.iter()),
        config.min_duplication_lines.to_string(),
        config.duplication_mode.clone(),
        config.complexity_threshold.to_string(),
        config.cognitive_threshold.to_string(),
        config.max_file_lines.to_string(),
        config.max_function_lines.to_string(),
        config.csharp_dead_code.to_string(),
        config.quality_profile.clone(),
        dart_list(config.quality_gates.iter()),
        dart_list(config.rule_groups.iter()),
        dart_list(
            config
                .group_modes
                .iter()
                .map(|(key, value)| format!("{key}={value}")),
        ),
        dart_list(
            config
                .rule_modes
                .iter()
                .map(|(key, value)| format!("{key}={value}")),
        ),
        dart_map(&config.severity_override_order),
        dart_list(config.disabled_rules.iter()),
        dart_pattern_rules(&config.pattern_rules),
        dart_list(config.structure_source_roots.iter()),
        config.structure_max_top_level_files.to_string(),
        dart_list(config.structure_allowed_top_level.iter()),
        dart_list(config.structure_required_directories.iter()),
        dart_list(config.architecture_layers.iter()),
        dart_list(config.architecture_allowed_dependencies.iter()),
        config.architecture_profile.clone(),
        dart_list(config.mvvm_views.iter()),
        dart_list(config.mvvm_view_models.iter()),
        dart_list(config.mvvm_models.iter()),
        dart_list(config.mvvm_repositories.iter()),
        config.mvvm_strict_view_model_boundary.to_string(),
        dart_list(config.architecture_denied_dependencies.iter()),
    ] {
        material.push_str(&line);
        material.push('\n');
    }
    let path = config.root.join("code-buster.toml");
    if let Ok(source) = std::fs::read_to_string(path) {
        material.push_str(&source);
        material.push('\n');
    }
    material
}

fn dart_list<I, T>(items: I) -> String
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    format!(
        "[{}]",
        items
            .into_iter()
            .map(|item| item.as_ref().to_owned())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn dart_map(values: &[(String, String)]) -> String {
    format!(
        "{{{}}}",
        values
            .iter()
            .map(|(key, value)| format!("{key}: RuleSeverity.{value}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn rule_version_signature() -> String {
    let mut signature = String::new();
    for (index, metadata) in rule_catalog::RULE_METADATA.iter().enumerate() {
        if index > 0 {
            signature.push(',');
        }
        signature.push_str(metadata.id);
        // `String`'s `fmt::Write` implementation is infallible.
        let _ = write!(signature, "@{}", metadata.version);
    }
    signature
}

fn dart_pattern_rules(rules: &[PatternRule]) -> String {
    let mut value = String::from("[");
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            value.push_str(", ");
        }
        // `String`'s `fmt::Write` implementation is infallible.
        let _ = write!(
            value,
            "{{id: {}, severity: {}, pattern: {}, patternNot: {}, message: {}, suggestion: {}, fix: {}, category: {}}}",
            rule.id,
            rule.severity.as_str(),
            rule.pattern,
            rule.pattern_not,
            rule.message,
            rule.suggestion,
            rule.fix,
            rule.category,
        );
    }
    value.push(']');
    value
}

fn git_revision(root: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", root, "rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!revision.is_empty()).then_some(revision)
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
