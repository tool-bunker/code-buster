use serde_json::{Value, json};

use crate::cli::PreviewOptions;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::summary_command;

pub enum WorkflowOutcome {
    Success,
    Findings,
}

pub fn execute_plan(options: &PreviewOptions) -> Result<(), String> {
    let run = summary_command::analyze(options)?;
    let mut groups = Vec::<(&str, Vec<&Finding>)>::new();
    for finding in &run.findings {
        if let Some((_, findings)) = groups
            .iter_mut()
            .find(|(code, _)| *code == finding.code.as_str())
        {
            findings.push(finding);
        } else {
            groups.push((&finding.code, vec![finding]));
        }
    }
    let mut prioritized = (0..groups.len()).collect::<Vec<_>>();
    crate::analysis_engine::dart_sort_indices(&mut prioritized, &|left, right| {
        let (left_code, left_findings) = &groups[left];
        let (right_code, right_findings) = &groups[right];
        priority_rank(left_code)
            .cmp(&priority_rank(right_code))
            .then_with(|| right_findings.len().cmp(&left_findings.len()))
    });

    println!("Code Buster review plan");
    if prioritized.is_empty() {
        println!("No findings to plan from.");
        return Ok(());
    }
    for (index, group_index) in prioritized.iter().enumerate() {
        let (code, findings) = &groups[*group_index];
        let worst = worst_severity(findings);
        println!(
            "{}. {} ({} finding{}, severity: {}, confidence: {})",
            index + 1,
            plan_title(code),
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            worst.as_str(),
            if *code == "feature-flag" {
                "medium"
            } else {
                "high"
            }
        );
        println!("   why: {}", action_why(code));
        println!("   suggestion: {}", action_suggestion(code));
        for finding in findings.iter().take(5) {
            println!("   - {}:{} {}", finding.path, finding.line, finding.message);
        }
        if findings.len() > 5 {
            println!("   - ... {} more", findings.len() - 5);
        }
    }
    Ok(())
}

pub fn execute_actions(options: &PreviewOptions) -> Result<WorkflowOutcome, String> {
    let run = summary_command::analyze(options)?;
    let actions = run
        .findings
        .iter()
        .map(action_value)
        .collect::<Vec<Value>>();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schemaVersion": 3,
            "version": 1,
            "command": "review",
            "view": "actions",
            "root": run.prepared.root,
            "actions": actions,
        }))
        .map_err(|error| format!("failed to encode actions report: {error}"))?
    );
    if options.fail_on_issues && !actions.is_empty() {
        Ok(WorkflowOutcome::Findings)
    } else {
        Ok(WorkflowOutcome::Success)
    }
}

fn action_value(finding: &Finding) -> Value {
    json!({
        "path": finding.path,
        "line": finding.line,
        "end_line": finding.end_line,
        "code": finding.code,
        "severity": finding.severity.as_str(),
        "risk": match finding.severity {
            Severity::Error => "high",
            Severity::Warn => "medium",
            Severity::Info => "low",
        },
        "problem": finding.message,
        "why": action_why(&finding.code),
        "suggested_action": action_suggestion(&finding.code),
        "related": finding.related_files,
    })
}

fn worst_severity(findings: &[&Finding]) -> Severity {
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        Severity::Error
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Warn)
    {
        Severity::Warn
    } else {
        Severity::Info
    }
}

fn plan_title(code: &str) -> String {
    match code {
        "cycle" => "Break cycle".to_owned(),
        "duplicate-block" => "Extract shared logic".to_owned(),
        "feature-flag" => "Review flag".to_owned(),
        "repeated-condition" => "Repeated condition".to_owned(),
        "structure-missing-required-dir" => "Structure missing required dir".to_owned(),
        "structure-top-level-file" => "Structure top level file".to_owned(),
        "tab-indent" => "Replace tabs".to_owned(),
        "trailing-whitespace" => "Trim whitespace".to_owned(),
        _ => rule_catalog::metadata(code).map_or_else(
            || format!("Review {}", code.replace('-', " ")),
            |metadata| metadata.title.to_owned(),
        ),
    }
}

fn action_why(code: &str) -> &'static str {
    match code {
        "cycle" => "A circular dependency exists in the module graph.",
        "duplicate-block" => "The same normalized code block appears in more than one location.",
        "feature-flag" => "A feature flag-like reference was found.",
        "tab-indent" => "A line contains a tab character.",
        "trailing-whitespace" => "A line has trailing whitespace.",
        _ => "A Code Buster heuristic analyzer found a potential issue.",
    }
}

fn action_suggestion(code: &str) -> &'static str {
    match code {
        "cycle" => "Extract shared code into a third module or invert one dependency.",
        "duplicate-block" => {
            "Extract shared logic or raise min_duplication_lines if the duplication is intentional/noisy."
        }
        "feature-flag" => "Review whether the flag is still needed and documented.",
        "tab-indent" => "Replace tabs with spaces.",
        "trailing-whitespace" => "Trim trailing spaces before committing.",
        _ => "Review the finding and update code or configuration as appropriate.",
    }
}

const PREFIX_PRIORITY_RANKS: &[(&str, u16)] = &[
    ("cs-", 100),
    ("cpp-", 120),
    ("java-", 140),
    ("lua-", 150),
    ("ts-", 160),
    ("py-", 170),
    ("html-", 180),
    ("css-", 180),
    ("sql-", 190),
    ("regex-", 200),
    ("nim-", 300),
];

fn priority_rank(code: &str) -> u16 {
    structural_priority_rank(code)
        .or_else(|| prefixed_priority_rank(code))
        .or_else(|| cleanup_priority_rank(code))
        .unwrap_or(500)
}

fn structural_priority_rank(code: &str) -> Option<u16> {
    match code {
        "cycle" => Some(0),
        "dead-file" => Some(10),
        "large-file" | "long-function" | "goto-statement" | "complex-function" => Some(20),
        "duplicate-block" => Some(30),
        "dead-export" | "feature-flag" | "re-export" => Some(40),
        _ => None,
    }
}

fn prefixed_priority_rank(code: &str) -> Option<u16> {
    PREFIX_PRIORITY_RANKS
        .iter()
        .find_map(|(prefix, rank)| code.starts_with(prefix).then_some(*rank))
}

fn cleanup_priority_rank(code: &str) -> Option<u16> {
    match code {
        "tab-indent" | "trailing-whitespace" | "long-line" => Some(900),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{action_suggestion, plan_title, priority_rank};

    #[test]
    fn prioritizes_structural_work_before_style_cleanup() {
        assert!(priority_rank("cycle") < priority_rank("duplicate-block"));
        assert!(priority_rank("duplicate-block") < priority_rank("tab-indent"));
    }

    #[test]
    fn uses_catalog_titles_and_specific_remediation() {
        assert_eq!(plan_title("dart-print"), "Review print");
        assert_eq!(action_suggestion("tab-indent"), "Replace tabs with spaces.");
    }
}
