use std::collections::BTreeMap;

use regex::Regex;

use crate::config::PatternRule;
use crate::findings::Finding;

pub fn analyze(
    sources: &BTreeMap<String, String>,
    rules: &[PatternRule],
) -> Result<Vec<Finding>, String> {
    let compiled = rules
        .iter()
        .map(CompiledPatternRule::new)
        .collect::<Result<Vec<_>, _>>()?;
    let mut findings = Vec::new();
    for (path, source) in sources {
        analyze_source(path, source, &compiled, &mut findings);
    }
    Ok(findings)
}

fn analyze_source(
    path: &str,
    source: &str,
    rules: &[CompiledPatternRule<'_>],
    findings: &mut Vec<Finding>,
) {
    for (index, line) in source.split('\n').enumerate() {
        let code = code_text(line);
        append_eligible_findings(path, index + 1, &code, rules, findings);
    }
}

fn append_eligible_findings(
    path: &str,
    line: usize,
    source: &str,
    rules: &[CompiledPatternRule<'_>],
    findings: &mut Vec<Finding>,
) {
    findings.extend(
        rules
            .iter()
            .filter(|rule| rule.is_eligible(source))
            .map(|rule| rule.finding(path, line)),
    );
}

struct CompiledPatternRule<'a> {
    rule: &'a PatternRule,
    patterns: Vec<Regex>,
    exclusions: Vec<Regex>,
}

impl<'a> CompiledPatternRule<'a> {
    fn new(rule: &'a PatternRule) -> Result<Self, String> {
        Ok(Self {
            rule,
            patterns: compile_expressions(&rule.pattern, &rule.id)?,
            exclusions: compile_expressions(&rule.pattern_not, &rule.id)?,
        })
    }

    fn is_eligible(&self, source: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(source))
            && !self
                .exclusions
                .iter()
                .any(|pattern| pattern.is_match(source))
    }

    fn finding(&self, path: &str, line: usize) -> Finding {
        let suggestion = if self.rule.fix.is_empty() {
            self.rule.suggestion.clone()
        } else if self.rule.suggestion.is_empty() {
            format!("Fix: {}", self.rule.fix)
        } else {
            format!("{} Fix: {}", self.rule.suggestion, self.rule.fix)
        };
        Finding {
            code: self.rule.id.clone(),
            severity: self.rule.severity,
            path: path.to_owned(),
            line,
            end_line: 0,
            message: if self.rule.message.is_empty() {
                "custom pattern matched".to_owned()
            } else {
                self.rule.message.clone()
            },
            confidence: "medium".to_owned(),
            why: if self.rule.category.is_empty() {
                "This finding was produced by a project-defined pattern rule.".to_owned()
            } else {
                format!(
                    "This finding was produced by a project-defined pattern rule in category `{}`.",
                    self.rule.category
                )
            },
            suggestion,
            related_files: Vec::new(),
            snippet: String::new(),
            code_flow: Vec::new(),
        }
    }
}

fn compile_expressions(value: &str, id: &str) -> Result<Vec<Regex>, String> {
    value
        .split(";;")
        .map(str::trim)
        .filter(|expression| !expression.is_empty())
        .map(|expression| {
            Regex::new(expression)
                .map_err(|error| format!("invalid pattern rule {id} expression: {error}"))
        })
        .collect()
}

static STRING_LITERAL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("custom-pattern string literal regex must compile")
});

fn code_text(line: &str) -> String {
    let masked = STRING_LITERAL.replace_all(line, " ");
    let slash = masked.find("//");
    let block = masked.find("/*");
    let marker = match (slash, block) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(index), None) | (None, Some(index)) => Some(index),
        (None, None) => None,
    };
    if let Some(index) = marker {
        masked[..index].to_owned()
    } else {
        masked.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use crate::findings::Severity;

    use super::*;

    #[test]
    fn evaluates_patterns_but_not_comments_strings_or_exclusions() {
        let rule = PatternRule {
            id: "no-debug".to_owned(),
            severity: Severity::Warn,
            pattern: r"debugCall\(".to_owned(),
            message: "debug call committed".to_owned(),
            suggestion: "Remove it.".to_owned(),
            pattern_not: "allowed".to_owned(),
            fix: "remove".to_owned(),
            category: "reliability".to_owned(),
        };
        let findings = analyze(
            &BTreeMap::from([(
                "lib/sample.dart".to_owned(),
                "debugCall(value);\n// debugCall(comment);\nfinal text = \"debugCall(string)\";\ndebugCall(allowed);\n"
                    .to_owned(),
            )]),
            &[rule],
        )
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].suggestion, "Remove it. Fix: remove");
        assert_eq!(findings[0].confidence, "medium");
    }

    #[test]
    fn supports_alternative_patterns_and_default_messages() {
        let rule = PatternRule {
            id: "forbidden-call".to_owned(),
            severity: Severity::Info,
            pattern: "firstCall;;secondCall".to_owned(),
            message: String::new(),
            suggestion: String::new(),
            pattern_not: String::new(),
            fix: "replace it".to_owned(),
            category: String::new(),
        };
        let findings = analyze(
            &BTreeMap::from([("src/main.ts".to_owned(), "secondCall();".to_owned())]),
            &[rule],
        )
        .unwrap();

        assert_eq!(findings[0].message, "custom pattern matched");
        assert_eq!(findings[0].suggestion, "Fix: replace it");
    }

    #[test]
    fn emits_same_line_matches_in_configuration_order() -> Result<(), String> {
        let first = PatternRule {
            id: "first-configured".to_owned(),
            severity: Severity::Info,
            pattern: "sharedCall".to_owned(),
            message: String::new(),
            suggestion: String::new(),
            pattern_not: String::new(),
            fix: String::new(),
            category: String::new(),
        };
        let second = PatternRule {
            id: "second-configured".to_owned(),
            ..first.clone()
        };

        let findings = analyze(
            &BTreeMap::from([("src/main.ts".to_owned(), "sharedCall();".to_owned())]),
            &[first, second],
        )?;

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec!["first-configured", "second-configured"]
        );

        Ok(())
    }
}
