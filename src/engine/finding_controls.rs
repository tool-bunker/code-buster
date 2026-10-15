use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::cli::PreviewOptions;
use crate::config::Config;
use crate::findings::{Finding, Severity, read_baseline};

pub struct ControlledFindings {
    pub active: Vec<Finding>,
    pub actionable: Vec<Finding>,
    pub actionable_count: usize,
    pub advisory_summary: BTreeMap<String, usize>,
}

pub fn apply(
    findings: Vec<Finding>,
    options: &PreviewOptions,
    config: &Config,
    sources: &BTreeMap<String, String>,
    taxonomy_group: fn(&str) -> &'static str,
) -> Result<ControlledFindings, String> {
    let baseline = read_baseline(options.baseline.as_deref())?;
    let mut active = Vec::new();
    let mut actionable = Vec::new();
    let mut actionable_count = 0;
    let mut advisory_summary = BTreeMap::new();
    for mut finding in findings {
        if !options.only.is_empty() && finding.code != options.only {
            continue;
        }
        if config.disabled_rules.contains(&finding.code)
            || baseline.contains(&finding.key())
            || baseline.contains(&finding.fingerprint())
            || is_suppressed(&finding, sources.get(&finding.path).map(String::as_str))
        {
            continue;
        }
        if let Some(severity) = config
            .severity_overrides
            .get(&finding.code)
            .and_then(|value| Severity::parse(value))
        {
            finding.severity = severity;
        }
        let group = taxonomy_group(&finding.code);
        match mode_for_code(&finding.code, config, group) {
            "off" => {}
            "count" => {
                *advisory_summary.entry(group.to_owned()).or_insert(0) += 1;
                active.push(finding.enrich());
            }
            _ => {
                let finding = finding.enrich();
                actionable_count += 1;
                actionable.push(finding.clone());
                active.push(finding);
            }
        }
    }
    Ok(ControlledFindings {
        active,
        actionable,
        actionable_count,
        advisory_summary,
    })
}

pub fn detailed(
    controlled: ControlledFindings,
    options: &PreviewOptions,
    taxonomy_group: fn(&str) -> &'static str,
) -> (Vec<Finding>, usize, BTreeMap<String, usize>) {
    let findings = if options.finding_group.is_empty() {
        controlled.active
    } else {
        controlled
            .active
            .into_iter()
            .filter(|finding| taxonomy_group(&finding.code) == options.finding_group)
            .collect()
    };
    (
        findings,
        controlled.actionable_count,
        controlled.advisory_summary,
    )
}

fn is_suppressed(finding: &Finding, source: Option<&str>) -> bool {
    let Some(source) = source else {
        return false;
    };
    for (index, line) in source.split('\n').enumerate() {
        let Some(directive) = comment_text(line) else {
            continue;
        };
        if let Some(rest) = directive.strip_prefix("code-buster-ignore-file")
            && targets_rule(rest, &finding.code)
        {
            return true;
        }
        if (index + 1).abs_diff(finding.line) <= 1
            && let Some(rest) = directive.strip_prefix("code-buster-ignore")
            && !directive.starts_with("code-buster-ignore-file")
            && targets_rule(rest, &finding.code)
        {
            return true;
        }
    }
    false
}

fn targets_rule(rest: &str, code: &str) -> bool {
    let trimmed = rest.trim();
    trimmed.is_empty()
        || trimmed.starts_with(':')
        || trimmed.split_whitespace().any(|token| {
            token
                .chars()
                .filter(|character| !matches!(character, ':' | ','))
                .eq(code.chars())
        })
}

fn comment_text(line: &str) -> Option<String> {
    let masked = STRING_LITERAL.replace_all(line, " ");
    let (index, marker) = ["//", "/*", "#", "--"]
        .into_iter()
        .filter_map(|marker| masked.find(marker).map(|index| (index, marker)))
        .min_by_key(|(index, _)| *index)?;
    Some(
        masked[index + marker.len()..]
            .trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '*' | '#' | '-')
            })
            .to_owned(),
    )
}

static STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("finding-control string literal regex must compile")
});

pub(crate) fn mode_for_code<'a>(code: &str, config: &'a Config, group: &str) -> &'a str {
    if let Some(mode) = config.rule_modes.get(code) {
        return mode;
    }
    if config.severity_overrides.contains_key(code) {
        return "report";
    }
    if let Some(mode) = config.group_modes.get(group) {
        return mode;
    }
    if matches!(
        code,
        "flutter-gesture-semantic-gap" | "flutter-listener-without-remove"
    ) {
        return "count";
    }
    if code.starts_with("dart-")
        && matches!(group, "correctness" | "reliability")
        && code != "dart-unreachable-statement"
    {
        return "count";
    }
    default_mode(group)
}

fn default_mode(group: &str) -> &'static str {
    match group {
        "core" | "correctness" | "security" | "reliability" | "accessibility" => "report",
        "architecture" | "game-engine" | "domain" | "experimental" => "off",
        _ => "count",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_adjacent_targeted_and_file_suppressions() {
        let source = "// code-buster-ignore complex-function\nvoid large() {}\n\
                      // code-buster-ignore-file dart-print\nvoid other() {}\n";

        assert!(is_suppressed(&finding("complex-function", 2), Some(source)));
        assert!(is_suppressed(&finding("dart-print", 40), Some(source)));
        assert!(!is_suppressed(&finding("duplicate-block", 2), Some(source)));
    }

    #[test]
    fn ignores_directive_text_inside_strings() {
        let source = "const value = '// code-buster-ignore';\nrun();\n";

        assert!(!is_suppressed(
            &finding("complex-function", 2),
            Some(source)
        ));
    }

    fn finding(code: &str, line: usize) -> Finding {
        Finding {
            code: code.to_owned(),
            severity: Severity::Warn,
            path: "lib/main.dart".to_owned(),
            line,
            end_line: line,
            message: String::new(),
            confidence: String::new(),
            why: String::new(),
            suggestion: String::new(),
            related_files: Vec::new(),
            snippet: String::new(),
            code_flow: Vec::new(),
        }
    }
}
