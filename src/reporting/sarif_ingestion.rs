use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};

use crate::discovery::ProcessingDiagnostic;
use crate::findings::{Finding, Severity};

pub(crate) struct SarifIngestion {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<ProcessingDiagnostic>,
}

pub(crate) fn read(reports: &[String], root: &Path) -> SarifIngestion {
    let mut findings = Vec::new();
    let mut diagnostics = Vec::new();
    for report in reports {
        match read_report(Path::new(report), root) {
            Ok(mut imported) => findings.append(&mut imported),
            Err(message) => diagnostics.push(ProcessingDiagnostic {
                code: "sarif-ingestion-failed",
                severity: "warning",
                stage: "ingestion",
                message,
                path: report.clone(),
            }),
        }
    }
    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.code.cmp(&right.code))
    });
    SarifIngestion {
        findings,
        diagnostics,
    }
}

fn read_report(report: &Path, root: &Path) -> Result<Vec<Finding>, String> {
    let bytes = fs::read(report).map_err(|error| error.to_string())?;
    let document: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let runs = document
        .get("runs")
        .and_then(Value::as_array)
        .ok_or_else(|| "expected a SARIF runs array".to_owned())?;
    let mut findings = Vec::new();
    for run in runs {
        let Some(run) = run.as_object() else { continue };
        let provider = provider(run);
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };
        findings.extend(
            results
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|result| finding(result, &provider, root)),
        );
    }
    Ok(findings)
}

fn provider(run: &Map<String, Value>) -> String {
    let name = run
        .get("tool")
        .and_then(|tool| tool.get("driver"))
        .and_then(|driver| driver.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty());
    name.map(slug)
        .unwrap_or_else(|| "external-sarif".to_owned())
}

fn finding(result: &Map<String, Value>, provider: &str, root: &Path) -> Option<Finding> {
    let rule = result.get("ruleId")?.as_str()?;
    let physical = result
        .get("locations")?
        .as_array()?
        .first()?
        .get("physicalLocation")?;
    let uri = physical.get("artifactLocation")?.get("uri")?.as_str()?;
    let relative = safe_relative_path(uri)?;
    if !root.join(&relative).starts_with(root) {
        return None;
    }
    let region = physical.get("region");
    let line = region
        .and_then(|value| value.get("startLine"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(1);
    let end_line = region
        .and_then(|value| value.get("endLine"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(line);
    let message = result
        .get("message")
        .and_then(|value| value.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("external SARIF finding")
        .to_owned();
    let severity = match result.get("level").and_then(Value::as_str) {
        Some("error") => Severity::Error,
        Some("warning") => Severity::Warn,
        _ => Severity::Info,
    };
    Some(Finding {
        code: format!("external:{provider}:{rule}"),
        severity,
        path: relative.to_string_lossy().replace('\\', "/"),
        line,
        end_line,
        message,
        confidence: "external".to_owned(),
        why: format!("Imported read-only from the attributed `{provider}` SARIF report."),
        suggestion: "Review remediation guidance from the originating analyzer.".to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    })
}

fn safe_relative_path(uri: &str) -> Option<PathBuf> {
    if uri.is_empty() || uri.starts_with('/') || uri.starts_with('\\') {
        return None;
    }
    let normalized = uri.replace('\\', "/");
    let first_segment = normalized.split('/').next()?;
    if first_segment.contains(':') {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(segment) => relative.push(segment),
            Component::CurDir => {}
            Component::ParentDir => {
                if !relative.pop() {
                    return None;
                }
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}

fn slug(value: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('-');
            }
            output.push(character);
            separator = false;
        } else {
            separator = true;
        }
    }
    output
}
