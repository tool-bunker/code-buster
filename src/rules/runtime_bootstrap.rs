use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut occurrences = BootstrapOccurrences::default();
    for (path, source) in context.sources() {
        if !is_test_path(path) {
            continue;
        }
        collect_process_bootstraps(path, source, &mut occurrences);
        collect_direct_bootstraps(path, source, &mut occurrences);
    }
    occurrences.into_findings()
}

#[derive(Clone)]
struct BootstrapTarget {
    tool: String,
    target: String,
}

struct BootstrapOccurrence {
    path: String,
    line: usize,
    tool: String,
    target: String,
}

#[derive(Default)]
struct BootstrapOccurrences {
    grouped: BTreeMap<String, Vec<BootstrapOccurrence>>,
    seen_locations: BTreeSet<String>,
}

impl BootstrapOccurrences {
    fn add(&mut self, target: BootstrapTarget, path: &str, line: usize) {
        let location = format!("{path}:{line}:{}:{}", target.tool, target.target);
        if !self.seen_locations.insert(location) {
            return;
        }
        let key = format!("{}:{}", target.tool, target.target);
        self.grouped
            .entry(key)
            .or_default()
            .push(BootstrapOccurrence {
                path: path.to_owned(),
                line,
                tool: target.tool,
                target: target.target,
            });
    }

    fn into_findings(self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mut occurrences in self.grouped.into_values() {
            occurrences.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then_with(|| left.line.cmp(&right.line))
            });
            if occurrences.len() < 3 {
                continue;
            }
            let reported = &occurrences[2];
            findings.push(finding(
                &reported.path,
                reported.line,
                format!(
                    "`{}` bootstraps `{}` {} times in tests",
                    reported.tool,
                    reported.target,
                    occurrences.len()
                ),
                occurrences
                    .iter()
                    .take(5)
                    .map(|occurrence| format!("{}:{}", occurrence.path, occurrence.line))
                    .collect(),
            ));
        }
        findings
    }
}

fn collect_process_bootstraps(path: &str, source: &str, occurrences: &mut BootstrapOccurrences) {
    for call in PROCESS_CALL.find_iter(source) {
        let mut end = (call.start() + 800).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let window = &source[call.start()..end];
        let tokens = QUOTED
            .captures_iter(window)
            .take(16)
            .filter_map(|capture| capture.get(1).map(|token| token.as_str().to_owned()))
            .collect::<Vec<_>>();
        if let Some(target) = target_from_tokens(window, &tokens) {
            occurrences.add(target, path, line_at(source, call.start()));
        }
    }
}

fn collect_direct_bootstraps(path: &str, source: &str, occurrences: &mut BootstrapOccurrences) {
    for (index, line) in source.split('\n').enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
            continue;
        }
        for command in DIRECT.captures_iter(line) {
            let Some(phrase) = command.get(1) else {
                continue;
            };
            let phrase = phrase.as_str().to_ascii_lowercase();
            let parts = phrase.split_whitespace().collect::<Vec<_>>();
            let Some(tool) = parts.first() else {
                continue;
            };
            let tool = (*tool).to_owned();
            let mut operation = parts.get(1).copied().unwrap_or("").to_owned();
            let argument = command.get(2).map(|value| value.as_str()).unwrap_or("");
            let mut arguments = vec![argument.to_owned()];
            if parts.len() == 1 && ["mvn", "mvnw", "gradle", "gradlew"].contains(&tool.as_str()) {
                operation = argument.to_owned();
                arguments.clear();
            }
            let target = BootstrapTarget {
                target: normalize_target(&tool, &operation, &arguments),
                tool,
            };
            occurrences.add(target, path, index + 1);
        }
    }
}

fn target_from_tokens(window: &str, tokens: &[String]) -> Option<BootstrapTarget> {
    if window.contains("Platform.resolvedExecutable") {
        let target = tokens.iter().find(|token| token.ends_with(".dart"))?;
        return Some(BootstrapTarget {
            tool: "dart".to_owned(),
            target: target.clone(),
        });
    }
    let (tool_index, tool) = tokens.iter().enumerate().find_map(|(index, token)| {
        let candidate = token
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(token)
            .to_ascii_lowercase();
        TOOLS
            .contains(&candidate.as_str())
            .then_some((index, candidate))
    })?;
    let mut arguments = tokens
        .iter()
        .skip(tool_index + 1)
        .cloned()
        .collect::<Vec<_>>();
    let operation = if arguments.is_empty() {
        String::new()
    } else {
        arguments.remove(0)
    };
    if ["dart", "cargo", "go", "dotnet"].contains(&tool.as_str()) && operation != "run" {
        return None;
    }
    Some(BootstrapTarget {
        target: normalize_target(&tool, &operation, &arguments),
        tool,
    })
}

fn normalize_target(tool: &str, operation: &str, arguments: &[String]) -> String {
    if tool == "cargo" {
        return option_value(arguments, "--bin").unwrap_or_else(|| "workspace".to_owned());
    }
    if tool == "dotnet" {
        return option_value(arguments, "--project").unwrap_or_else(|| "project".to_owned());
    }
    if ["mvn", "mvnw", "gradle", "gradlew"].contains(&tool) {
        return if operation.is_empty() {
            "default task".to_owned()
        } else {
            operation.to_owned()
        };
    }
    arguments
        .iter()
        .find(|argument| !argument.is_empty() && !argument.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "default target".to_owned())
}

fn option_value(arguments: &[String], option: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == option)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}

fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    TEST_DIRECTORY.is_match(&normalized) || TEST_FILE.is_match(name)
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn finding(path: &str, line: usize, message: String, related_files: Vec<String>) -> Finding {
    let metadata = rule_catalog::metadata("test-repeated-runtime-bootstrap")
        .expect("runtime bootstrap metadata must exist");
    Finding {
        code: metadata.id.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("runtime bootstrap severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: "medium".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files,
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

const TOOLS: &[&str] = &[
    "dart", "cargo", "go", "dotnet", "mvn", "mvnw", "gradle", "gradlew",
];

static PROCESS_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Process\.(?:run|start)|subprocess\.(?:run|Popen|call)|child_process\.(?:spawn|execFile)|spawn|execFile|execa)\s*\(").unwrap()
});
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"[\"']([^\"']+)[\"']"#).unwrap());
static DIRECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(dart\s+run|cargo\s+run|go\s+run|dotnet\s+run|mvnw?|gradlew?)\s+([^\s\"']+)?"#,
    )
    .unwrap()
});
static TEST_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|/)(?:test|tests|spec|specs|__tests__)(/|$)").unwrap());
static TEST_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:_test\.dart|\.test\.[a-z]+|\.spec\.[a-z]+|^test_.*\.py$)").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_repeated_dart_entrypoint() {
        let sources = ["first", "second", "third"]
            .into_iter()
            .map(|name| {
                (
                    format!("test/{name}_test.dart"),
                    "final result = await Process.run(\n  Platform.resolvedExecutable,\n  <String>[\"bin/tool.dart\", \"--version\"],\n);"
                        .to_owned(),
                )
            })
            .collect();
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("dart"));
        assert!(findings[0].message.contains("bin/tool.dart"));
        assert!(findings[0].message.contains("3 times"));
    }

    #[test]
    fn detects_repeated_cargo_go_and_gradle_bootstraps() {
        let source = "subprocess.run([\"cargo\", \"run\", \"--bin\", \"server\"])\nos.system(\"go run cmd/check.go\")\nos.system(\"./gradlew test\")";
        let sources = ["one", "two", "three"]
            .into_iter()
            .map(|name| (format!("tests/{name}.py"), source.to_owned()))
            .collect();
        let context = SourceAnalysisContext::unchanged(&sources);
        let findings = analyze(&context);

        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("cargo"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("go"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("gradlew"))
        );
    }

    #[test]
    fn ignores_production_launches_and_distinct_test_targets() {
        let sources = BTreeMap::from([
            (
                "lib/launcher.dart".to_owned(),
                "const command = \"dart run bin/tool.dart\";".to_owned(),
            ),
            (
                "test/tools_test.dart".to_owned(),
                "const first = \"dart run bin/one.dart\";\nconst second = \"dart run bin/two.dart\";\nconst third = \"dart run bin/three.dart\";"
                    .to_owned(),
            ),
        ]);
        let context = SourceAnalysisContext::unchanged(&sources);

        assert!(analyze(&context).is_empty());
    }
}
