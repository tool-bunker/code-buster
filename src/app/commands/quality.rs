use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Number, Value, json};

use crate::cli::{PreviewOptions, ReportFormat};
use crate::findings::{Finding, Severity};
use crate::report::{FindingReport, manifest};
use crate::rule_catalog;
use crate::summary_command;

pub enum QualityOutcome {
    Success,
    Findings,
}

pub fn execute_score(options: &PreviewOptions) -> Result<(), String> {
    let run = summary_command::analyze(options)?;
    let dead = paths_with_code(&run.findings, "dead-file");
    let duplicate = paths_with_code(&run.findings, "duplicate-block");
    let cycle = paths_with_code(&run.findings, "cycle");
    println!("Code Buster score: {} files", run.prepared.files.len());
    for file in &run.prepared.files {
        let mut score = 100.0;
        let mut reasons = Vec::new();
        if dead.contains(&file.path) {
            score -= 30.0;
            reasons.push("dead file (-30.0)");
        }
        if cycle.contains(&file.path) {
            score -= 15.0;
            reasons.push("part of a cycle (-15.0)");
        }
        if duplicate.contains(&file.path) {
            score -= 10.0;
            reasons.push("has duplicated content (-10.0)");
        }
        let suffix = if reasons.is_empty() {
            String::new()
        } else {
            format!(" {}", reasons.join(", "))
        };
        println!("{:>5.1} {}{suffix}", score, file.path);
    }
    Ok(())
}

pub fn execute_quality(options: &PreviewOptions) -> Result<QualityOutcome, String> {
    let run = prepare_quality_input(options)?;
    let evaluation = evaluate_quality(&run);
    let gate_passed = evaluation.gate_passed;
    render_quality(options, &run, evaluation)?;
    Ok(decide_quality_status(options.fail_on_issues, gate_passed))
}

fn prepare_quality_input(options: &PreviewOptions) -> Result<summary_command::AnalysisRun, String> {
    summary_command::analyze(options)
}

struct QualityEvaluation {
    severity: SeverityCounts,
    totals: QualityTotals,
    debt_per_file: f64,
    rating: &'static str,
    modules: BTreeMap<String, ModuleMeasures>,
    numeric_measures: BTreeMap<String, f64>,
    gate_conditions: Vec<Value>,
    gate_passed: bool,
}

struct SeverityCounts {
    errors: usize,
    warnings: usize,
    info: usize,
}

#[derive(Default)]
struct QualityTotals {
    debt: usize,
    domains: BTreeMap<String, usize>,
    domain_debt: BTreeMap<String, usize>,
    security_hotspots: usize,
    security_vulnerabilities: usize,
}

fn evaluate_quality(run: &summary_command::AnalysisRun) -> QualityEvaluation {
    let severity = count_severities(&run.actionable_findings);
    let totals = collect_quality_totals(&run.actionable_findings);
    let divisor = run.prepared.files.len().max(1) as f64;
    let debt_per_file = round_two(totals.debt as f64 / divisor);
    let rating = quality_rating(debt_per_file);
    let modules = collect_module_measures(run);
    let numeric_measures = build_numeric_measures(run, &severity, &totals, debt_per_file);
    let gate_conditions = run
        .prepared
        .config
        .quality_gates
        .iter()
        .map(|condition| evaluate_gate(condition, &numeric_measures))
        .collect::<Vec<_>>();
    let gate_passed = gate_conditions
        .iter()
        .all(|condition| condition["passed"] == Value::Bool(true));

    QualityEvaluation {
        severity,
        totals,
        debt_per_file,
        rating,
        modules,
        numeric_measures,
        gate_conditions,
        gate_passed,
    }
}

fn count_severities(findings: &[Finding]) -> SeverityCounts {
    let errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warn)
        .count();
    SeverityCounts {
        errors,
        warnings,
        info: findings.len() - errors - warnings,
    }
}

fn collect_quality_totals(findings: &[Finding]) -> QualityTotals {
    let mut totals = QualityTotals::default();
    let mut debt_groups = BTreeSet::new();
    for finding in findings {
        let metadata = rule_catalog::metadata(&finding.code);
        match metadata.map_or("none", |metadata| metadata.security_kind) {
            "hotspot" => totals.security_hotspots += 1,
            "vulnerability" => totals.security_vulnerabilities += 1,
            _ => {}
        }
        let domain = quality_domain(&finding.code);
        *totals.domains.entry(domain.to_owned()).or_default() += 1;
        if debt_groups.insert(quality_debt_group(finding)) {
            let minutes = debt_minutes(finding) + occurrence_debt_minutes(finding);
            totals.debt += minutes;
            *totals.domain_debt.entry(domain.to_owned()).or_default() += minutes;
        }
    }
    totals
}

fn collect_module_measures(run: &summary_command::AnalysisRun) -> BTreeMap<String, ModuleMeasures> {
    let mut modules = BTreeMap::<String, ModuleMeasures>::new();
    for file in &run.prepared.files {
        modules
            .entry(module_for_path(&file.path))
            .or_default()
            .files += 1;
    }
    for finding in &run.actionable_findings {
        let module = modules.entry(module_for_path(&finding.path)).or_default();
        module.findings += 1;
        module.debt_minutes += debt_minutes(finding);
    }
    modules
}

fn build_numeric_measures(
    run: &summary_command::AnalysisRun,
    severity: &SeverityCounts,
    totals: &QualityTotals,
    debt_per_file: f64,
) -> BTreeMap<String, f64> {
    let advisory_total = run.advisory_summary.values().sum::<usize>();
    let mut measures = BTreeMap::<String, f64>::from([
        ("files".to_owned(), run.prepared.files.len() as f64),
        ("findings".to_owned(), run.actionable_findings.len() as f64),
        ("errors".to_owned(), severity.errors as f64),
        ("warnings".to_owned(), severity.warnings as f64),
        ("info".to_owned(), severity.info as f64),
        ("debt_minutes".to_owned(), totals.debt as f64),
        ("debt_minutes_per_file".to_owned(), debt_per_file),
        (
            "security_findings".to_owned(),
            totals.domains.get("security").copied().unwrap_or_default() as f64,
        ),
        (
            "security_hotspots".to_owned(),
            totals.security_hotspots as f64,
        ),
        (
            "security_vulnerabilities".to_owned(),
            totals.security_vulnerabilities as f64,
        ),
        (
            "reliability_findings".to_owned(),
            totals
                .domains
                .get("reliability")
                .copied()
                .unwrap_or_default() as f64,
        ),
        (
            "selected_files".to_owned(),
            run.prepared
                .coverage
                .get("selected")
                .copied()
                .unwrap_or(run.prepared.files.len()) as f64,
        ),
        ("advisory.total".to_owned(), advisory_total as f64),
    ]);
    for (group, count) in &run.advisory_summary {
        measures.insert(format!("advisory.{group}"), *count as f64);
    }
    measures
}

fn quality_rating(debt_per_file: f64) -> &'static str {
    match debt_per_file {
        0.0 => "A",
        value if value <= 5.0 => "B",
        value if value <= 15.0 => "C",
        value if value <= 30.0 => "D",
        _ => "E",
    }
}

fn render_quality(
    options: &PreviewOptions,
    run: &summary_command::AnalysisRun,
    evaluation: QualityEvaluation,
) -> Result<(), String> {
    if matches!(options.format, ReportFormat::Json) {
        render_quality_json(options, run, evaluation)
    } else {
        render_quality_text(run, &evaluation);
        Ok(())
    }
}

fn render_quality_json(
    options: &PreviewOptions,
    run: &summary_command::AnalysisRun,
    evaluation: QualityEvaluation,
) -> Result<(), String> {
    let QualityEvaluation {
        severity,
        totals,
        debt_per_file,
        rating,
        modules,
        numeric_measures,
        gate_conditions,
        gate_passed,
    } = evaluation;
    let SeverityCounts {
        errors,
        warnings,
        info,
    } = severity;
    let QualityTotals {
        debt,
        domains,
        domain_debt,
        ..
    } = totals;

    let mut measures = Map::new();
    for (name, value) in &numeric_measures {
        measures.insert(
            name.clone(),
            typed_numeric_value(*value, name == "debt_minutes_per_file"),
        );
    }
    let module_values = modules
        .into_iter()
        .map(|(name, values)| {
            (
                name,
                json!({
                    "files": values.files,
                    "findings": values.findings,
                    "debt_minutes": values.debt_minutes,
                }),
            )
        })
        .collect::<Map<_, _>>();
    let severity = json!({"info": info, "warn": warnings, "error": errors});
    let report = FindingReport {
        command: "summary",
        prepared: &run.prepared,
        findings: &run.actionable_findings,
        actionable_count: run.actionable_count,
        advisory_summary: &run.advisory_summary,
        show_advisory_hint: false,
        verbose: options.verbose,
        profile: options.profile,
    };
    let mut result = Map::new();
    result.insert("schemaVersion".to_owned(), json!(3));
    result.insert("version".to_owned(), json!(1));
    result.insert("command".to_owned(), json!("quality"));
    result.insert(
        "scope".to_owned(),
        json!(if run.prepared.config.changed_lines {
            "changed-lines"
        } else {
            "repository"
        }),
    );
    result.insert("files".to_owned(), json!(run.prepared.files.len()));
    result.insert("findings".to_owned(), json!(run.actionable_findings.len()));
    if run.prepared.config.changed_lines {
        result.insert(
            "new_findings".to_owned(),
            json!(run.actionable_findings.len()),
        );
    }
    if !run.prepared.coverage.is_empty() {
        result.insert("coverage".to_owned(), json!(run.prepared.coverage));
    }
    if !run.prepared.diagnostics.is_empty() {
        result.insert(
            "processingDiagnostics".to_owned(),
            json!(run.prepared.diagnostics),
        );
    }
    result.insert("manifest".to_owned(), manifest(&report));
    result.insert(
        "gate".to_owned(),
        json!(if gate_passed { "pass" } else { "fail" }),
    );
    result.insert("measureSchemaVersion".to_owned(), json!(1));
    result.insert("measures".to_owned(), Value::Object(measures));
    result.insert("modules".to_owned(), Value::Object(module_values));
    result.insert("gate_conditions".to_owned(), json!(gate_conditions));
    result.insert("rating".to_owned(), json!(rating));
    result.insert("debt_minutes".to_owned(), json!(debt));
    result.insert("debt_minutes_per_file".to_owned(), json!(debt_per_file));
    result.insert("domains".to_owned(), json!(domains));
    result.insert("domain_debt_minutes".to_owned(), json!(domain_debt));
    result.insert("severity".to_owned(), severity);

    println!(
        "{}",
        serde_json::to_string(&Value::Object(result))
            .map_err(|error| format!("failed to encode quality report: {error}"))?
    );
    Ok(())
}

fn render_quality_text(run: &summary_command::AnalysisRun, evaluation: &QualityEvaluation) {
    println!(
        "Code Buster quality: {} files, {} findings",
        run.prepared.files.len(),
        run.actionable_findings.len()
    );
    println!(
        "gate: {} scope={}",
        if evaluation.gate_passed {
            "pass"
        } else {
            "fail"
        },
        if run.prepared.config.changed_lines {
            "changed-lines"
        } else {
            "repository"
        }
    );
    println!(
        "rating: {} debt_minutes={}",
        evaluation.rating, evaluation.totals.debt
    );
    println!(
        "domains: maintainability={} reliability={} security={}",
        evaluation
            .totals
            .domains
            .get("maintainability")
            .copied()
            .unwrap_or_default(),
        evaluation
            .totals
            .domains
            .get("reliability")
            .copied()
            .unwrap_or_default(),
        evaluation
            .totals
            .domains
            .get("security")
            .copied()
            .unwrap_or_default()
    );
    println!(
        "severity: error={} warn={} info={}",
        evaluation.severity.errors, evaluation.severity.warnings, evaluation.severity.info
    );
}

fn decide_quality_status(fail_on_issues: bool, gate_passed: bool) -> QualityOutcome {
    if fail_on_issues && !gate_passed {
        QualityOutcome::Findings
    } else {
        QualityOutcome::Success
    }
}

#[derive(Default)]
struct ModuleMeasures {
    files: usize,
    findings: usize,
    debt_minutes: usize,
}

fn paths_with_code(findings: &[Finding], code: &str) -> BTreeSet<String> {
    findings
        .iter()
        .filter(|finding| finding.code == code)
        .map(|finding| finding.path.clone())
        .collect()
}

fn quality_domain(code: &str) -> &'static str {
    let Some(metadata) = rule_catalog::metadata(code) else {
        return "maintainability";
    };
    for taxonomy in [
        "security",
        "reliability",
        "correctness",
        "architecture",
        "performance",
        "design",
        "maintainability",
        "style",
    ] {
        if metadata.taxonomy.contains(&taxonomy) {
            return taxonomy;
        }
    }
    "maintainability"
}

fn quality_debt_group(finding: &Finding) -> String {
    if matches!(
        finding.code.as_str(),
        "duplicate-block" | "repeated-condition"
    ) && !finding.related_files.is_empty()
    {
        let own = if finding.code == "duplicate-block" {
            format!("{}:{}-{}", finding.path, finding.line, finding.end_line)
        } else {
            format!("{}:{}", finding.path, finding.line)
        };
        let mut locations = Vec::with_capacity(finding.related_files.len() + 1);
        locations.push(own);
        locations.extend(finding.related_files.iter().cloned());
        locations.sort_unstable();
        return format!("{}|{}", finding.code, locations.join("|"));
    }
    finding.fingerprint()
}

fn occurrence_debt_minutes(finding: &Finding) -> usize {
    let per_occurrence = match finding.severity {
        Severity::Error => 5,
        Severity::Warn => 2,
        Severity::Info => 1,
    };
    finding.related_files.len().min(10) * per_occurrence
}

fn debt_minutes(finding: &Finding) -> usize {
    match finding.severity {
        Severity::Error => 60,
        Severity::Warn => 30,
        Severity::Info => 5,
    }
}

fn module_for_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let segments = normalized.split('/').collect::<Vec<_>>();
    if segments.len() >= 2
        && ["packages", "plugins", "modules", "apps", "services"].contains(&segments[0])
    {
        return format!("{}/{}", segments[0], segments[1]);
    }
    if let Some(index) = segments.iter().position(|segment| *segment == "src")
        && index > 0
    {
        return segments[..index].join("/");
    }
    "root".to_owned()
}

fn evaluate_gate(condition: &str, measures: &BTreeMap<String, f64>) -> Value {
    let Some(captures) = GATE.captures(condition) else {
        return json!({
            "condition": condition,
            "passed": false,
            "error": "unknown or invalid measure condition",
        });
    };
    let (Some(metric), Some(operator), Some(expected_text)) =
        (captures.get(1), captures.get(2), captures.get(3))
    else {
        return invalid_gate(condition);
    };
    let metric = metric.as_str();
    let Some(actual) = measures.get(metric).copied() else {
        return json!({
            "condition": condition,
            "passed": false,
            "error": "unknown or invalid measure condition",
        });
    };
    let operator = operator.as_str();
    let expected_text = expected_text.as_str();
    let Ok(expected) = expected_text.parse::<f64>() else {
        return invalid_gate(condition);
    };
    let passed = match operator {
        "==" => actual == expected,
        "!=" => actual != expected,
        "<=" => actual <= expected,
        ">=" => actual >= expected,
        "<" => actual < expected,
        ">" => actual > expected,
        _ => false,
    };
    json!({
        "condition": condition,
        "measure": metric,
        "operator": operator,
        "expected": typed_numeric_value(expected, expected_text.contains('.')),
        "actual": typed_numeric_value(actual, metric == "debt_minutes_per_file"),
        "passed": passed,
    })
}

fn invalid_gate(condition: &str) -> Value {
    json!({
        "condition": condition,
        "passed": false,
        "error": "unknown or invalid measure condition",
    })
}

fn typed_numeric_value(value: f64, decimal: bool) -> Value {
    if decimal {
        Number::from_f64(value).map_or(Value::Null, Value::Number)
    } else {
        numeric_value(value)
    }
}

fn numeric_value(value: f64) -> Value {
    if value.fract() == 0.0 {
        json!(value as u64)
    } else {
        Number::from_f64(value).map_or(Value::Null, Value::Number)
    }
}

fn round_two(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

static GATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*([a-z][a-z0-9_.]*)\s*(==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)?)\s*$")
        .expect("quality gate regex must compile")
});

#[cfg(test)]
mod tests {
    use super::{evaluate_gate, module_for_path};
    use std::collections::BTreeMap;

    #[test]
    fn evaluates_known_and_unknown_quality_gates() {
        let measures = BTreeMap::from([("findings".to_owned(), 2.0)]);
        assert_eq!(evaluate_gate("findings <= 2", &measures)["passed"], true);
        assert_eq!(evaluate_gate("missing == 0", &measures)["passed"], false);
    }

    #[test]
    fn groups_monorepo_and_source_root_modules() {
        assert_eq!(module_for_path("packages/api/lib/a.dart"), "packages/api");
        assert_eq!(module_for_path("engine/src/main.rs"), "engine");
        assert_eq!(module_for_path("lib/main.dart"), "root");
    }
}
