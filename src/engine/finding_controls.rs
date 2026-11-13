use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::Config;
use crate::findings::{Finding, Severity, read_baseline};
use crate::options::PreviewOptions;

pub struct ControlledFindings {
    pub active: Vec<Finding>,
    pub actionable: Vec<Finding>,
    pub actionable_count: usize,
    pub advisory_summary: BTreeMap<String, usize>,
}

impl ControlledFindings {
    fn record(&mut self, finding: Finding, mode: &str, group: &str) {
        match mode {
            "off" => {}
            "count" => {
                *self.advisory_summary.entry(group.to_owned()).or_insert(0) += 1;
                self.active.push(finding.enrich());
            }
            _ => {
                let finding = finding.enrich();
                self.actionable_count += 1;
                self.actionable.push(finding.clone());
                self.active.push(finding);
            }
        }
    }
}

pub fn apply(
    findings: Vec<Finding>,
    options: &PreviewOptions,
    config: &Config,
    sources: &BTreeMap<String, String>,
    taxonomy_group: fn(&str) -> &'static str,
) -> Result<ControlledFindings, String> {
    let baseline = read_baseline(options.baseline.as_deref())?;
    let has_baseline = !baseline.is_empty();
    let mut suppressions = SuppressionIndex::new(sources);
    let mut controlled = ControlledFindings {
        active: Vec::new(),
        actionable: Vec::new(),
        actionable_count: 0,
        advisory_summary: BTreeMap::new(),
    };
    for mut finding in findings {
        if !options.only.is_empty() && finding.code != options.only {
            continue;
        }
        if config.disabled_rules.contains(&finding.code)
            || (has_baseline
                && (baseline.contains(&finding.key()) || baseline.contains(&finding.fingerprint())))
            || suppressions.suppresses(&finding)
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
        let mode = mode_for_code(&finding.code, config, group);
        controlled.record(finding, mode, group);
    }
    Ok(controlled)
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

struct SuppressionIndex<'source> {
    sources: &'source BTreeMap<String, String>,
    directives: BTreeMap<&'source str, Vec<SuppressionDirective>>,
}

impl<'source> SuppressionIndex<'source> {
    fn new(sources: &'source BTreeMap<String, String>) -> Self {
        Self {
            sources,
            directives: BTreeMap::new(),
        }
    }

    fn suppresses(&mut self, finding: &Finding) -> bool {
        let Some((path, source)) = self.sources.get_key_value(&finding.path) else {
            return false;
        };
        let directives = self
            .directives
            .entry(path)
            .or_insert_with(|| suppression_directives(source));
        directives_suppress(directives, finding)
    }
}

struct SuppressionDirective {
    line: usize,
    file: bool,
    target: String,
}

fn suppression_directives(source: &str) -> Vec<SuppressionDirective> {
    if !source.contains("code-buster-ignore") {
        return Vec::new();
    }
    source
        .split('\n')
        .enumerate()
        .filter_map(|(index, line)| {
            let directive = comment_text(line)?;
            if let Some(target) = directive.strip_prefix("code-buster-ignore-file") {
                return Some(SuppressionDirective {
                    line: index + 1,
                    file: true,
                    target: target.to_owned(),
                });
            }
            directive
                .strip_prefix("code-buster-ignore")
                .map(|target| SuppressionDirective {
                    line: index + 1,
                    file: false,
                    target: target.to_owned(),
                })
        })
        .collect()
}

fn directives_suppress(directives: &[SuppressionDirective], finding: &Finding) -> bool {
    directives.iter().any(|directive| {
        (directive.file || directive.line.abs_diff(finding.line) <= 1)
            && targets_rule(&directive.target, &finding.code)
    })
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
        "flutter-gesture-semantic-gap"
            | "flutter-listener-without-remove"
            | "py-exception-swallowed"
            | "py-raise-destroys-traceback"
            | "py-resource-not-closed"
            | "py-subprocess-no-timeout"
            | "py-unbounded-retry-loop"
            | "py-unsafe-archive-extract"
            | "java-empty-catch"
            | "shell-ignored-command-failure"
            | "shell-unquoted-expansion"
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

        assert!(suppressed(source, &finding("complex-function", 2)));
        assert!(suppressed(source, &finding("dart-print", 40)));
        assert!(!suppressed(source, &finding("duplicate-block", 2)));
    }

    #[test]
    fn ignores_directive_text_inside_strings() {
        let source = "const value = '// code-buster-ignore';\nrun();\n";

        assert!(!suppressed(source, &finding("complex-function", 2)));
    }

    #[test]
    fn applies_new_python_rule_groups_and_default_modes() {
        let mut config = Config::defaults(std::path::PathBuf::new());
        for (code, expected_group, expected_mode) in [
            ("py-coroutine-not-awaited", "correctness", "report"),
            ("py-exception-swallowed", "reliability", "count"),
            ("py-resource-not-closed", "reliability", "count"),
            ("py-finally-control-flow", "correctness", "report"),
            ("py-unsafe-archive-extract", "security", "count"),
            ("py-insecure-random-token", "security", "report"),
            ("py-query-in-loop", "performance", "count"),
            ("py-subprocess-no-timeout", "reliability", "count"),
            ("py-unbounded-retry-loop", "reliability", "count"),
            ("py-raise-destroys-traceback", "correctness", "count"),
            ("py-sensitive-data-logging", "security", "report"),
            ("py-test-mocked-target-wrong", "correctness", "report"),
        ] {
            let group = crate::rule_catalog::descriptor(code)
                .expect("new Python rule must be registered")
                .group;
            assert_eq!(group, expected_group, "{code}");
            assert_eq!(mode_for_code(code, &config, group), expected_mode, "{code}");
        }

        config
            .rule_modes
            .insert("py-subprocess-no-timeout".to_owned(), "report".to_owned());
        assert_eq!(
            mode_for_code("py-subprocess-no-timeout", &config, "reliability"),
            "report"
        );
    }

    #[test]
    fn keeps_intent_dependent_advice_out_of_actionable_findings_by_default() {
        let mut config = Config::defaults(std::path::PathBuf::new());
        for code in [
            "java-empty-catch",
            "shell-ignored-command-failure",
            "shell-unquoted-expansion",
        ] {
            let group = crate::rule_catalog::descriptor(code)
                .expect("rule must be registered")
                .group;
            assert_eq!(mode_for_code(code, &config, group), "count", "{code}");
        }

        config
            .rule_modes
            .insert("shell-unquoted-expansion".to_owned(), "report".to_owned());
        assert_eq!(
            mode_for_code("shell-unquoted-expansion", &config, "correctness"),
            "report"
        );
    }

    fn suppressed(source: &str, finding: &Finding) -> bool {
        directives_suppress(&suppression_directives(source), finding)
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
