use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::rule_catalog;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeFlowStep {
    pub path: String,
    pub line: usize,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub path: String,
    pub line: usize,
    pub end_line: usize,
    pub message: String,
    pub confidence: String,
    pub why: String,
    pub suggestion: String,
    pub related_files: Vec<String>,
    pub snippet: String,
    pub code_flow: Vec<CodeFlowStep>,
}

impl Finding {
    pub fn structure(
        code: &str,
        path: String,
        message: String,
        suggestion: &str,
        related_files: Vec<String>,
    ) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Warn,
            path,
            line: 1,
            end_line: 0,
            message,
            confidence: String::new(),
            why: String::new(),
            suggestion: suggestion.to_owned(),
            related_files,
            snippet: String::new(),
            code_flow: Vec::new(),
        }
    }

    pub fn enrich(mut self) -> Self {
        if self.confidence.is_empty() {
            self.confidence = if self.severity == Severity::Error {
                "high".to_owned()
            } else {
                "medium".to_owned()
            };
        }
        if self.why.is_empty() {
            self.why = rule_why(&self.code).to_owned();
        }
        if self.suggestion.is_empty() {
            self.suggestion = rule_suggestion(&self.code).to_owned();
        }
        self
    }

    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.code, self.path, self.message)
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.key().as_bytes());
        format!("{digest:X}")[..12].to_owned()
    }

    pub fn to_json(&self) -> Value {
        let mut finding = json!({
            "code": self.code,
            "severity": self.severity.as_str(),
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "message": self.message,
            "confidence": self.confidence,
            "why": self.why,
            "suggestion": self.suggestion,
            "related_files": self.related_files,
            "snippet": self.snippet,
        });
        let Some(object) = finding.as_object_mut() else {
            return finding;
        };
        if let Some(metadata) = rule_catalog::metadata(&self.code)
            && metadata.security_kind != "none"
        {
            object.insert(
                "security_kind".to_owned(),
                Value::String(metadata.security_kind.to_owned()),
            );
        }
        if !self.code_flow.is_empty() {
            object.insert(
                "code_flow".to_owned(),
                Value::Array(
                    self.code_flow
                        .iter()
                        .map(|step| {
                            json!({
                                "path": step.path,
                                "line": step.line,
                                "message": step.message,
                            })
                        })
                        .collect(),
                ),
            );
        }
        finding
    }
}

pub fn rule_why(code: &str) -> &'static str {
    match code {
        "duplicate-block" => "The same normalized code block appears in more than one location.",
        "complex-function" => "The function exceeds configured complexity thresholds.",
        "feature-flag" => "A feature/config flag reference was found.",
        "dead-file" | "dead-export" => {
            "The symbol or file was not reached by the heuristic dependency graph."
        }
        _ => "This finding was produced by a Code Buster heuristic analyzer.",
    }
}

pub fn rule_suggestion(code: &str) -> &'static str {
    match code {
        "duplicate-block" => "Extract shared logic or raise min_duplication_lines if intentional.",
        "complex-function" => "Split branches into smaller helpers or simplify control flow.",
        "feature-flag" => "Review ownership and lifecycle for this flag.",
        "dead-file" | "dead-export" => {
            "Remove it or add an entry point/reference if it is loaded dynamically."
        }
        _ => "Review the finding and update code or configuration as appropriate.",
    }
}

pub fn read_baseline(path: Option<&Path>) -> Result<BTreeSet<String>, String> {
    let Some(path) = path else {
        return Ok(BTreeSet::new());
    };
    if !path.is_file() {
        return Ok(BTreeSet::new());
    }
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read baseline {}: {error}", path.display()))?;
    Ok(normalize_baseline(parse_baseline_document(&content)))
}

enum BaselineDocument<'a> {
    Ledger(Value),
    Legacy(&'a str),
}

fn parse_baseline_document(content: &str) -> BaselineDocument<'_> {
    match serde_json::from_str(content) {
        Ok(document) => BaselineDocument::Ledger(document),
        Err(_) => BaselineDocument::Legacy(content),
    }
}

fn normalize_baseline(document: BaselineDocument<'_>) -> BTreeSet<String> {
    match document {
        BaselineDocument::Ledger(document) => normalize_ledger(&document),
        BaselineDocument::Legacy(content) => content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect(),
    }
}

fn normalize_ledger(document: &Value) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let Some(entries) = select_baseline_entries(document) else {
        return result;
    };
    for entry in entries.iter().filter_map(convert_baseline_entry) {
        if let Some((code, path, message)) = entry.identity {
            result.insert(format!("{code}|{path}|{message}"));
        }
        if let Some(fingerprint) = entry.fingerprint {
            result.insert(fingerprint.to_owned());
        }
    }
    result
}

fn select_baseline_entries(document: &Value) -> Option<&[Value]> {
    document
        .as_object()
        .and_then(|object| object.get("entries"))
        .unwrap_or(document)
        .as_array()
        .map(Vec::as_slice)
}

struct BaselineEntry<'a> {
    identity: Option<(&'a str, &'a str, &'a str)>,
    fingerprint: Option<&'a str>,
}

fn convert_baseline_entry(value: &Value) -> Option<BaselineEntry<'_>> {
    let entry = value.as_object()?;
    if entry
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| !["accepted", "false-positive", "wont-fix"].contains(&status))
        || entry
            .get("expiry")
            .and_then(Value::as_str)
            .is_some_and(expiry_is_past)
    {
        return None;
    }
    let identity = match (
        entry.get("code").and_then(Value::as_str),
        entry.get("path").and_then(Value::as_str),
        entry.get("message").and_then(Value::as_str),
    ) {
        (Some(code), Some(path), Some(message)) => Some((code, path, message)),
        _ => None,
    };
    let fingerprint = entry
        .get("fingerprint")
        .and_then(Value::as_str)
        .filter(|fingerprint| !fingerprint.is_empty());
    Some(BaselineEntry {
        identity,
        fingerprint,
    })
}

fn expiry_is_past(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let expiry = OffsetDateTime::parse(value, &Rfc3339).or_else(|_| {
        Date::parse(
            value,
            time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map(|date| PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc())
    });
    expiry.is_ok_and(|expiry| expiry < OffsetDateTime::now_utc())
}
