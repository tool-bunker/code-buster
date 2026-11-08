use std::collections::BTreeMap;
use std::path::Path;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

mod codeowners;
mod feature_flags;
mod toolchains;
mod typescript;
mod workspaces;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let auxiliary = context.auxiliary_files();
    let mut findings = typescript::analyze(auxiliary);
    findings.extend(feature_flags::analyze(auxiliary));
    findings.extend(codeowners::analyze(auxiliary));
    findings.extend(workspaces::analyze(auxiliary));
    findings.extend(toolchains::analyze(auxiliary));
    findings
}

pub(crate) fn codeowners_existence_markers(
    root: &Path,
    auxiliary: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    codeowners::existence_markers(root, auxiliary)
}

pub(crate) fn strip_jsonc_comments(source: &str) -> String {
    typescript::strip_jsonc_comments(source)
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: String,
    related_files: Vec<String>,
) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("repository policy metadata must exist");
    Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("repository policy severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: line,
        message,
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

fn line_containing(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map_or(1, |index| index + 1)
}
