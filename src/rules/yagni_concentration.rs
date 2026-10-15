use std::collections::{BTreeMap, BTreeSet};

use crate::config::Config;
use crate::finding_controls;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;

type FindingsByPath<'a> = BTreeMap<&'a str, Vec<&'a Finding>>;

struct QualifiedGroup<'a> {
    path: &'a str,
    findings: Vec<&'a Finding>,
    rule_ids: BTreeSet<&'a str>,
}

pub fn analyze(findings: &[Finding], config: &Config) -> Vec<Finding> {
    let grouped = group_findings(findings, config);
    let qualified = qualify_groups(grouped);
    emit_findings(qualified, concentration_severity(config))
}

fn group_findings<'a>(findings: &'a [Finding], config: &Config) -> FindingsByPath<'a> {
    let mut by_path = FindingsByPath::new();
    for finding in findings {
        if finding.path.is_empty()
            || finding.code == "yagni-concentration"
            || !is_active_yagni_rule(&finding.code, config)
        {
            continue;
        }
        by_path
            .entry(finding.path.as_str())
            .or_default()
            .push(finding);
    }
    by_path
}

fn qualify_groups<'a>(grouped: FindingsByPath<'a>) -> impl Iterator<Item = QualifiedGroup<'a>> {
    grouped
        .into_iter()
        .filter_map(|(path, findings)| qualify_group(path, findings))
}

fn qualify_group<'a>(path: &'a str, mut findings: Vec<&'a Finding>) -> Option<QualifiedGroup<'a>> {
    findings.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.code.cmp(&right.code))
    });
    let rule_ids = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<BTreeSet<_>>();
    (findings.len() >= 3 && rule_ids.len() >= 2).then_some(QualifiedGroup {
        path,
        findings,
        rule_ids,
    })
}

fn emit_findings<'a>(
    groups: impl Iterator<Item = QualifiedGroup<'a>>,
    severity: Severity,
) -> Vec<Finding> {
    groups
        .into_iter()
        .map(|group| {
            let rule_list = format_rule_list(&group.rule_ids);
            Finding {
                code: "yagni-concentration".to_owned(),
                severity,
                path: group.path.to_owned(),
                line: group.findings[0].line,
                end_line: 0,
                message: format!(
                    "{} YAGNI findings from {} rule families are concentrated in this file: {}",
                    group.findings.len(),
                    group.rule_ids.len(),
                    rule_list
                ),
                confidence: "medium".to_owned(),
                why: "Several independent signs of unused flexibility or one-use indirection in one file suggest the design should be reviewed as a whole instead of fixing each symptom separately.".to_owned(),
                suggestion: "Start from the actual callers and required behavior, then remove unused variation and collapse one-use layers together; retain boundaries that own policy, validation, lifecycle, or an external contract.".to_owned(),
                related_files: Vec::new(),
                snippet: String::new(),
                code_flow: Vec::new(),
            }
        })
        .collect()
}

fn format_rule_list(rule_ids: &BTreeSet<&str>) -> String {
    let mut rule_list = String::new();
    for rule_id in rule_ids {
        if !rule_list.is_empty() {
            rule_list.push_str(", ");
        }
        rule_list.push_str(rule_id);
    }
    rule_list
}

fn concentration_severity(config: &Config) -> Severity {
    config
        .severity_overrides
        .get("yagni-concentration")
        .and_then(|value| Severity::parse(value))
        .unwrap_or(Severity::Info)
}

fn is_active_yagni_rule(code: &str, config: &Config) -> bool {
    if config.disabled_rules.contains(code)
        || rule_catalog::metadata(code).is_none_or(|metadata| metadata.legacy_group != "yagni")
    {
        return false;
    }
    let group =
        rule_catalog::descriptor(code).map_or("maintainability", |descriptor| descriptor.group);
    finding_controls::mode_for_code(code, config, group) != "off"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(code: &str, line: usize) -> Finding {
        Finding {
            code: code.to_owned(),
            severity: Severity::Info,
            path: "lib/service.dart".to_owned(),
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

    #[test]
    fn requires_density_diversity_and_active_source_rules() {
        let wrappers = vec![
            finding("single-use-trivial-wrapper", 2),
            finding("single-use-trivial-wrapper", 4),
            finding("single-use-trivial-wrapper", 6),
        ];
        let constant = finding("constant-argument-parameter", 8);
        let config = Config::defaults(".".into());

        assert!(analyze(&wrappers, &config).is_empty());
        assert!(analyze(&[wrappers[0].clone(), constant.clone()], &config).is_empty());
        assert_eq!(
            analyze(
                &[wrappers[0].clone(), wrappers[1].clone(), constant.clone()],
                &config,
            )
            .len(),
            1
        );

        let mut disabled = config;
        disabled
            .disabled_rules
            .insert("constant-argument-parameter".to_owned());
        assert!(
            analyze(
                &[wrappers[0].clone(), wrappers[1].clone(), constant],
                &disabled,
            )
            .is_empty()
        );
    }
}
