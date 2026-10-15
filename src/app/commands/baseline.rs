use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::cli::RepositoryViewOptions;
use crate::findings::{Finding, Severity, read_baseline};
use crate::rule_catalog;
use crate::summary_command;

pub enum BaselineOutcome {
    Success,
    Empty,
}

pub fn execute(options: &RepositoryViewOptions) -> Result<BaselineOutcome, String> {
    let run = summary_command::analyze(&options.common)?;
    if run.prepared.files.is_empty() && !options.common.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(BaselineOutcome::Empty);
    }
    let output = options
        .common
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&run.prepared.root).join(".code-buster-baseline"));
    let mut findings = nim_generic_findings(&run.prepared.files, &run.prepared.sources);
    findings.extend(run.findings);
    let existing = read_baseline(Some(&output))?;
    let current = finding_keys(&findings);
    match options.targets.first().map(String::as_str) {
        Some("stats") => {
            let matched = existing.intersection(&current).count();
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "version": 1,
                    "command": "baseline stats",
                    "entries": existing.len(),
                    "matched": matched,
                    "stale": existing.difference(&current).count(),
                    "current_findings": findings.len(),
                }))
                .map_err(|error| format!("failed to encode baseline statistics: {error}"))?
            );
        }
        target => {
            if target == Some("prune") {
                findings.retain(|finding| {
                    existing.contains(&finding.key()) || existing.contains(&finding.fingerprint())
                });
            }
            write_baseline(&output, &findings)?;
            let action = match target {
                Some("prune") => "pruned baseline",
                Some("update") => "updated baseline",
                _ => "wrote baseline",
            };
            println!("{action} {}", output.display());
        }
    }
    Ok(BaselineOutcome::Success)
}

fn finding_keys(findings: &[Finding]) -> BTreeSet<String> {
    findings
        .iter()
        .flat_map(|finding| [finding.key(), finding.fingerprint()])
        .collect()
}

fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let existing = baseline_metadata(path)?;
    let entries = findings
        .iter()
        .map(|finding| {
            let fingerprint = finding.fingerprint();
            let mut entry = Map::new();
            entry.insert("status".to_owned(), json!("accepted"));
            entry.insert("reason".to_owned(), json!("baseline snapshot"));
            entry.insert("owner".to_owned(), json!(""));
            entry.insert("expiry".to_owned(), json!(""));
            entry.insert(
                "rule_version".to_owned(),
                json!(rule_catalog::metadata(&finding.code).map_or(1, |metadata| metadata.version)),
            );
            entry.insert("source_fingerprint".to_owned(), json!(fingerprint));
            entry.insert(
                "history".to_owned(),
                json!([{
                    "from": Value::Null,
                    "to": "accepted",
                    "reason": "baseline snapshot",
                }]),
            );
            if let Some(metadata) = existing.get(&fingerprint) {
                entry.extend(metadata.clone());
            }
            entry.insert("fingerprint".to_owned(), json!(fingerprint));
            if let Value::Object(mut current) = finding.to_json() {
                current.remove("security_kind");
                entry.extend(current);
            }
            Value::Object(entry)
        })
        .collect::<Vec<_>>();
    let encoded = serde_json::to_string_pretty(&json!({
        "schemaVersion": 2,
        "kind": "code-buster-triage-ledger",
        "entries": entries,
    }))
    .map_err(|error| format!("failed to encode baseline {}: {error}", path.display()))?;
    fs::write(path, encoded)
        .map_err(|error| format!("failed to write baseline {}: {error}", path.display()))
}

fn baseline_metadata(path: &Path) -> Result<BTreeMap<String, Map<String, Value>>, String> {
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read baseline {}: {error}", path.display()))?;
    let Ok(decoded) = serde_json::from_str::<Value>(&source) else {
        return Ok(BTreeMap::new());
    };
    let entries = decoded
        .as_object()
        .and_then(|object| object.get("entries"))
        .unwrap_or(&decoded);
    let mut metadata = BTreeMap::new();
    for raw in entries.as_array().into_iter().flatten() {
        let Some(entry) = raw.as_object() else {
            continue;
        };
        let Some(fingerprint) = entry
            .get("fingerprint")
            .and_then(Value::as_str)
            .filter(|fingerprint| !fingerprint.is_empty())
        else {
            continue;
        };
        metadata.insert(fingerprint.to_owned(), entry.clone());
    }
    Ok(metadata)
}

fn nim_generic_findings(
    files: &[crate::discovery::SourceFile],
    sources: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in files.iter().filter(|file| file.language == "nim") {
        let Some(source) = sources.get(&file.path) else {
            continue;
        };
        for (index, raw_line) in source.split('\n').enumerate() {
            let declaration = raw_line.trim();
            if declaration.starts_with("import ") || declaration.starts_with("from ") {
                continue;
            }
            let Some(open) = declaration.find('[').filter(|open| *open > 0) else {
                continue;
            };
            let Some(relative_close) = declaration[open + 1..].find(']') else {
                continue;
            };
            let close = open + 1 + relative_close;
            let usage = &declaration[close + 1..];
            for parameter in declaration[open + 1..close]
                .split(',')
                .filter_map(generic_parameter)
            {
                if contains_identifier(usage, parameter) {
                    continue;
                }
                findings.push(Finding {
                    code: "unused-generic-parameter".to_owned(),
                    severity: Severity::Warn,
                    path: file.path.clone(),
                    line: index + 1,
                    end_line: index + 1,
                    message: format!(
                        "generic parameter '{parameter}' is not used by type {}",
                        declaration[..open].trim()
                    ),
                    confidence: "high".to_owned(),
                    why: "An unused type parameter adds a distinct type dimension without changing stored data or behavior.".to_owned(),
                    suggestion: "Remove the parameter unless phantom typing is an intentional, documented constraint.".to_owned(),
                    related_files: Vec::new(),
                    snippet: declaration.to_owned(),
                    code_flow: Vec::new(),
                });
            }
        }
    }
    findings
}

fn generic_parameter(value: &str) -> Option<&str> {
    let name = value.trim().split(':').next()?.trim();
    (!name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        }))
    .then_some(name)
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(index, _)| {
        let before = source[..index].bytes().next_back();
        let after = source[index + identifier.len()..].bytes().next();
        !before.is_some_and(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            && !after.is_some_and(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::{contains_identifier, generic_parameter};

    #[test]
    fn recognizes_nim_generic_names_and_real_usage() {
        assert_eq!(generic_parameter("T: typedesc"), Some("T"));
        assert_eq!(generic_parameter("7bad"), None);
        assert!(contains_identifier("value: T", "T"));
        assert!(!contains_identifier("value: Thing", "T"));
    }
}
