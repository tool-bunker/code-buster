use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

const TEMPLATE_INJECTION: &str = "github-actions-template-injection";
const MUTABLE_ACTION_REFERENCE: &str = "github-actions-mutable-reference";
const PULL_REQUEST_TARGET_CHECKOUT: &str = "github-actions-pull-request-target-checkout";

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in context
        .auxiliary_files()
        .iter()
        .filter(|(path, _)| is_github_workflow(path))
    {
        let structure = workflow_structure(source);
        findings.extend(template_injections(path, source, &structure));
        if let Some(finding) = mutable_action_references(path, &structure) {
            findings.push(finding);
        }
        if workflow_uses_pull_request_target(&structure) {
            findings.extend(pull_request_target_checkouts(path, source, &structure));
        }
    }
    findings
}

fn is_github_workflow(path: &str) -> bool {
    let path = Path::new(path);
    path.parent() == Some(Path::new(".github/workflows"))
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "yml" | "yaml"))
}

#[derive(Clone, Copy)]
struct RunBlock {
    indentation: usize,
    start: usize,
    line: usize,
}

#[derive(Default)]
struct SafeInputs {
    direct: BTreeSet<String>,
    event: BTreeSet<String>,
}

fn template_injections(path: &str, source: &str, structure: &[&str]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let safe_inputs = typed_safe_inputs(structure);
    let mut block: Option<RunBlock> = None;
    let mut offset = 0;

    for (index, segment) in source.split_inclusive('\n').enumerate() {
        let line = segment.trim_end_matches(['\r', '\n']);
        let start = offset;
        offset += segment.len();
        if let Some(active) = block {
            if line.trim().is_empty() || indentation(line) > active.indentation {
                continue;
            }
            report_template_injection(
                &mut findings,
                path,
                &source[active.start..start],
                active.line,
                &safe_inputs,
            );
            block = None;
        }
        let Some(value) = yaml_value(structure[index], "run") else {
            continue;
        };
        if is_block_scalar(value) {
            block = Some(RunBlock {
                indentation: mapping_indentation(line),
                start: offset,
                line: index + 2,
            });
        } else {
            report_template_injection(&mut findings, path, value, index + 1, &safe_inputs);
        }
    }
    if let Some(active) = block {
        report_template_injection(
            &mut findings,
            path,
            &source[active.start..],
            active.line,
            &safe_inputs,
        );
    }
    findings
}

fn report_template_injection(
    findings: &mut Vec<Finding>,
    path: &str,
    script: &str,
    line: usize,
    safe_inputs: &SafeInputs,
) {
    if let Some(offset) = untrusted_expression_offset(script, safe_inputs) {
        findings.push(finding(
            TEMPLATE_INJECTION,
            path,
            line + script[..offset]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            "Untrusted GitHub Actions data is interpolated directly into a shell command"
                .to_owned(),
        ));
    }
}

fn mutable_action_references(path: &str, structure: &[&str]) -> Option<Finding> {
    let mut mutable = Vec::new();
    for (index, line) in structure.iter().enumerate() {
        if mutable_action_reference(line).is_some() {
            mutable.push(index + 1);
        }
    }
    let first = *mutable.first()?;
    Some(finding(
        MUTABLE_ACTION_REFERENCE,
        path,
        first,
        format!(
            "{} external action reference{} in this workflow {} not pinned to full commit SHAs",
            mutable.len(),
            if mutable.len() == 1 { "" } else { "s" },
            if mutable.len() == 1 { "is" } else { "are" }
        ),
    ))
}

fn mutable_action_reference(line: &str) -> Option<&str> {
    let value = scalar_value(yaml_value(line, "uses")?)?;
    if value.starts_with("./") || value.starts_with("docker://") {
        return None;
    }
    let (action, reference) = value.rsplit_once('@')?;
    if !action.contains('/') || reference.is_empty() || is_full_commit_sha(reference) {
        return None;
    }
    Some(action)
}

fn yaml_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }
    let candidate = trimmed.strip_prefix("- ").map_or(trimmed, str::trim_start);
    let value = candidate.strip_prefix(key)?.strip_prefix(':')?;
    Some(value.trim_start())
}

fn is_block_scalar(value: &str) -> bool {
    value.starts_with(['|', '>'])
}

fn scalar_value(value: &str) -> Option<&str> {
    let value = value.trim();
    let first = value.chars().next()?;
    if matches!(first, '\'' | '"') {
        let rest = &value[first.len_utf8()..];
        return rest.find(first).map(|end| &rest[..end]);
    }
    value.split_whitespace().next()
}

fn is_full_commit_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn indentation(line: &str) -> usize {
    line.chars()
        .take_while(|character| character.is_whitespace())
        .count()
}

fn mapping_indentation(line: &str) -> usize {
    let sequence_offset = if line.trim_start().starts_with("- ") {
        2
    } else {
        0
    };
    indentation(line) + sequence_offset
}

// Preserve line numbers and mapping headers, but do not mistake script, env,
// description, or other block-scalar contents for workflow structure.
fn workflow_structure(source: &str) -> Vec<&str> {
    let mut scalar_indentation = None;
    source
        .lines()
        .map(|line| {
            if let Some(active) = scalar_indentation {
                if line.trim().is_empty() || indentation(line) > active {
                    return "";
                }
                scalar_indentation = None;
            }
            if !line.trim_start().starts_with('#')
                && line
                    .split_once(':')
                    .is_some_and(|(_, value)| is_block_scalar(value.trim_start()))
            {
                scalar_indentation = Some(mapping_indentation(line));
            }
            line
        })
        .collect()
}

fn untrusted_expression_offset(value: &str, safe_inputs: &SafeInputs) -> Option<usize> {
    let complete = WORKFLOW_EXPRESSION
        .captures_iter(value)
        .find_map(|capture| {
            let expression = capture[1].trim();
            if SAFE_EVENT_EXPRESSION.is_match(expression) {
                return None;
            }
            if let Some(input) = INPUT_EXPRESSION.captures(expression) {
                let complete = input
                    .get(0)
                    .is_some_and(|matched| matched.as_str() == expression);
                let typed = input.get(1).or_else(|| input.get(2)).is_some_and(|name| {
                    let safe = if expression.starts_with("github.event.") {
                        &safe_inputs.event
                    } else {
                        &safe_inputs.direct
                    };
                    safe.contains(name.as_str())
                });
                if complete && typed {
                    return None;
                }
            }
            (UNTRUSTED_EVENT_EXPRESSION.is_match(expression)
                || INPUT_EXPRESSION.is_match(expression))
            .then(|| {
                capture
                    .get(0)
                    .expect("expression capture must exist")
                    .start()
            })
        });
    complete.or_else(|| {
        // Quoted YAML scalars can continue on the next line. Preserve evidence
        // already visible on the run header even when its closing delimiter is
        // outside the line-oriented structural parser.
        let start = value.rfind("${{")?;
        let tail = &value[start + 3..];
        (!tail.contains("}}")
            && (UNTRUSTED_EVENT_EXPRESSION.is_match(tail) || INPUT_EXPRESSION.is_match(tail)))
        .then_some(start)
    })
}

fn typed_safe_inputs(lines: &[&str]) -> SafeInputs {
    let mut safe = SafeInputs::default();
    for (index, line) in lines.iter().enumerate() {
        let Some(kind) = yaml_value(line, "type").and_then(scalar_value) else {
            continue;
        };
        if !matches!(kind, "boolean" | "number") {
            continue;
        }
        let Some((input_index, input_indent, input)) =
            parent_mapping(lines, index, indentation(line))
        else {
            continue;
        };
        let Some((inputs_index, inputs_indent, parent)) =
            parent_mapping(lines, input_index, input_indent)
        else {
            continue;
        };
        let Some((event_index, event_indent, event)) =
            parent_mapping(lines, inputs_index, inputs_indent)
        else {
            continue;
        };
        let event_is_workflow_input = matches!(event, "workflow_dispatch" | "workflow_call")
            && parent_mapping(lines, event_index, event_indent)
                .is_some_and(|(_, indent, key)| indent == 0 && key == "on");
        if parent == "inputs" && event_is_workflow_input {
            safe.direct.insert(input.to_owned());
            if event == "workflow_dispatch" {
                safe.event.insert(input.to_owned());
            }
        }
    }
    safe
}

fn parent_mapping<'a>(
    lines: &[&'a str],
    before: usize,
    child_indent: usize,
) -> Option<(usize, usize, &'a str)> {
    lines[..before]
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, line)| !line.trim().is_empty())
        .find_map(|(index, line)| {
            let indent = indentation(line);
            (indent < child_indent)
                .then(|| yaml_mapping_key(line).map(|key| (index, indent, key)))
                .flatten()
        })
}

// code-buster-ignore complex-function: YAML event nesting is resolved by one indentation-aware scan.
fn workflow_uses_pull_request_target(lines: &[&str]) -> bool {
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = yaml_value(line, "on") else {
            continue;
        };
        if yaml_token(value, "pull_request_target") {
            return true;
        }
        if !value.trim().is_empty() {
            continue;
        }
        let parent_indentation = indentation(line);
        for nested in &lines[index + 1..] {
            if nested.trim().is_empty() || nested.trim_start().starts_with('#') {
                continue;
            }
            if indentation(nested) <= parent_indentation {
                break;
            }
            if yaml_value(nested, "pull_request_target").is_some() {
                return true;
            }
        }
    }
    false
}

fn yaml_token(value: &str, expected: &str) -> bool {
    value
        .split(|character: char| {
            character.is_whitespace() || matches!(character, '[' | ']' | ',' | '\'' | '"' | '#')
        })
        .any(|token| token == expected)
}

fn pull_request_target_checkouts(path: &str, source: &str, structure: &[&str]) -> Vec<Finding> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut findings = Vec::new();
    let ranges = job_ranges(structure);
    let global_end = ranges.first().map_or(structure.len(), |(start, _)| *start);
    let global_overrides =
        has_execution_configuration(&lines[..global_end], &structure[..global_end]);
    for (start, end) in ranges {
        let allow_metadata = !global_overrides
            && !has_execution_configuration(&lines[start..end], &structure[start..end]);
        for index in start..end {
            let Some(action) = yaml_value(structure[index], "uses").and_then(scalar_value) else {
                continue;
            };
            if !action.starts_with("actions/checkout@") {
                continue;
            }
            let step_end = step_end(structure, index, end);
            if checkout_uses_untrusted_head(&structure[index + 1..step_end])
                && job_executes_checkout(
                    &lines[step_end..end],
                    &structure[step_end..end],
                    checkout_path(&structure[index + 1..step_end]),
                    allow_metadata,
                )
            {
                findings.push(finding(
                    PULL_REQUEST_TARGET_CHECKOUT,
                    path,
                    index + 1,
                    "Untrusted pull-request code is checked out and executed by a privileged pull_request_target job"
                        .to_owned(),
                ));
            }
        }
    }
    findings
}

fn job_ranges(lines: &[&str]) -> Vec<(usize, usize)> {
    let Some((jobs_index, jobs_indentation)) =
        lines.iter().enumerate().find_map(|(index, line)| {
            yaml_value(line, "jobs")
                .is_some_and(|value| value.trim().is_empty())
                .then(|| (index, indentation(line)))
        })
    else {
        return Vec::new();
    };
    let Some(job_indentation) = lines[jobs_index + 1..]
        .iter()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|line| indentation(line))
        .find(|indentation| *indentation > jobs_indentation)
    else {
        return Vec::new();
    };
    let starts = lines[jobs_index + 1..]
        .iter()
        .enumerate()
        .filter_map(|(offset, line)| {
            (indentation(line) == job_indentation && yaml_mapping_key(line).is_some())
                .then_some(jobs_index + 1 + offset)
        })
        .collect::<Vec<_>>();
    starts
        .iter()
        .enumerate()
        .map(|(index, start)| {
            let end = starts
                .get(index + 1)
                .copied()
                .unwrap_or_else(|| workflow_section_end(lines, *start, jobs_indentation));
            (*start, end)
        })
        .collect()
}

fn yaml_mapping_key(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.starts_with(['#', '-']) {
        return None;
    }
    let (key, _) = trimmed.split_once(':')?;
    (!key.trim().is_empty()).then_some(key.trim())
}

fn workflow_section_end(lines: &[&str], start: usize, parent_indentation: usize) -> usize {
    lines[start + 1..]
        .iter()
        .position(|line| {
            !line.trim().is_empty()
                && !line.trim_start().starts_with('#')
                && indentation(line) <= parent_indentation
        })
        .map_or(lines.len(), |offset| start + 1 + offset)
}

fn step_end(lines: &[&str], start: usize, job_end: usize) -> usize {
    let step_indentation = indentation(lines[start]);
    lines[start + 1..job_end]
        .iter()
        .position(|line| {
            !line.trim().is_empty()
                && indentation(line) <= step_indentation
                && line.trim_start().starts_with("- ")
        })
        .map_or(job_end, |offset| start + 1 + offset)
}

fn checkout_uses_untrusted_head(lines: &[&str]) -> bool {
    lines.iter().any(|line| {
        ["ref", "repository"].iter().any(|key| {
            yaml_value(line, key).is_some_and(|value| {
                WORKFLOW_EXPRESSION.captures_iter(value).any(|capture| {
                    capture[1].contains("github.event.pull_request.head.")
                        || capture[1].contains("github.head_ref")
                })
            })
        })
    })
}

fn checkout_path<'a>(lines: &[&'a str]) -> Option<&'a str> {
    let path = lines
        .iter()
        .find_map(|line| yaml_value(line, "path").and_then(scalar_value))
        .unwrap_or(".");
    (!path.contains("${{")).then_some(path)
}

fn has_execution_configuration(lines: &[&str], structure: &[&str]) -> bool {
    lines.iter().any(|line| {
        line.contains("git config ")
            || [
                "GIT_EXTERNAL_DIFF",
                "GIT_CONFIG",
                "GIT_EXEC_PATH",
                "GIT_SSH",
                "GIT_PROXY_COMMAND",
                "BASH_ENV",
                "SHELLOPTS",
                "BASHOPTS",
            ]
            .iter()
            .any(|key| line.contains(key))
    }) || structure.iter().any(|line| {
        yaml_value(line, "shell")
            .is_some_and(|shell| !matches!(shell.trim(), "bash" | "sh" | "bash {0}" | "sh {0}"))
    })
}

fn job_executes_checkout(
    lines: &[&str],
    structure: &[&str],
    path: Option<&str>,
    allow_metadata: bool,
) -> bool {
    for (index, line) in structure.iter().enumerate() {
        let action = yaml_value(line, "uses").and_then(scalar_value);
        if action.is_some_and(|action| action.starts_with("./")) {
            return true;
        }
        if action.is_some_and(|action| action.starts_with("actions/checkout@"))
            && clean_checkout_replaces_path(structure, index, path)
        {
            return false;
        }
        if let Some(value) = yaml_value(line, "run") {
            let end = step_end(structure, index, structure.len());
            if !allow_metadata || !run_only_inspects_metadata(&lines[index..end], value) {
                return true;
            }
        }
    }
    false
}

fn clean_checkout_replaces_path(structure: &[&str], index: usize, path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let start = structure[..=index]
        .iter()
        .rposition(|line| line.trim_start().starts_with("- "))
        .unwrap_or(index);
    let end = step_end(structure, index, structure.len());
    let step = &structure[start..end];
    if checkout_path(step) != Some(path) {
        return false;
    }
    !step.iter().any(|line| {
        yaml_value(line, "if").is_some()
            || yaml_value(line, "clean")
                .and_then(scalar_value)
                .is_some_and(|value| value != "true")
    })
}

fn run_only_inspects_metadata(lines: &[&str], value: &str) -> bool {
    if is_block_scalar(value) {
        let run_indentation = mapping_indentation(lines[0]);
        lines[1..]
            .iter()
            .take_while(|line| line.trim().is_empty() || indentation(line) > run_indentation)
            .all(|line| metadata_only_command(line.trim()))
    } else {
        let value = value.trim();
        let value = if value.starts_with(['\'', '"']) {
            &value[1..value.len().saturating_sub(1)]
        } else {
            value
        };
        metadata_only_command(value)
    }
}

// A narrow command allowlist proves that a run step reads Git metadata rather
// than executing the checkout. Unknown shell syntax and execution options remain
// findings; in particular, command substitution is never a harmless echo.
fn metadata_only_command(command: &str) -> bool {
    if command.is_empty() || command.starts_with('#') {
        return true;
    }
    if has_unsupported_shell_syntax(command) {
        return false;
    }
    if let Some(message) = command.strip_prefix("echo ") {
        return metadata_only_echo(message);
    }
    if command.contains(['<', '>']) {
        return false;
    }
    if let Some(arguments) = command.strip_prefix("git fetch ") {
        return METADATA_FETCH_ARGUMENTS.is_match(arguments);
    }
    command
        .strip_prefix("git diff ")
        .is_some_and(|arguments| arguments.split_whitespace().all(metadata_diff_argument))
}

fn has_unsupported_shell_syntax(command: &str) -> bool {
    const UNSUPPORTED_TOKENS: &[&str] = &[
        ";", "|", "&", "`", "\\", "\n", "\r", "$(", "<(", ">(", "${{", "$[",
    ];
    if UNSUPPORTED_TOKENS
        .iter()
        .any(|token| command.contains(token))
    {
        return true;
    }
    command
        .match_indices("${")
        .any(|(start, _)| !plain_shell_parameter(&command[start + 2..]))
}

fn plain_shell_parameter(tail: &str) -> bool {
    let Some((name, _)) = tail.split_once('}') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn metadata_only_echo(message: &str) -> bool {
    if !message.contains(['<', '>']) {
        return true;
    }
    let Some((message, target)) = message.rsplit_once(">>") else {
        return false;
    };
    if message.contains(['<', '>']) {
        return false;
    }
    matches!(
        target.trim(),
        "$GITHUB_OUTPUT" | "\"$GITHUB_OUTPUT\"" | "${GITHUB_OUTPUT}" | "\"${GITHUB_OUTPUT}\""
    )
}

fn metadata_diff_argument(argument: &str) -> bool {
    matches!(
        argument,
        "--" | "--exit-code"
            | "--quiet"
            | "--name-only"
            | "--name-status"
            | "--stat"
            | "--no-ext-diff"
            | "--no-textconv"
    ) || (!argument.starts_with('-')
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_$}{/.-".contains(&byte)))
}

fn finding(code: &str, path: &str, line: usize, message: String) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("GitHub Actions rule metadata must exist");
    Finding {
        code: metadata.id.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("GitHub Actions rule severity must be valid"),
        path: path.to_owned(),
        line,
        end_line: 0,
        message,
        confidence: "high".to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    }
}

static WORKFLOW_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\$\{\{(.*?)\}\}").expect("GitHub Actions expression regex must compile")
});
static UNTRUSTED_EVENT_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:github\.event(?:\.|\[)|github\.head_ref\b)")
        .expect("GitHub Actions event expression regex must compile")
});
// Only complete expressions qualify. Hashes and numeric event identifiers have
// constrained values; names, refs, titles, and fallbacks do not.
static SAFE_EVENT_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:github\.event\.(?:number|after|before|pull_request\.(?:number|(?:base|head)\.sha)|workflow_run\.head_sha|repository\.default_branch))$",
    )
    .expect("safe GitHub event expression regex must compile")
});
static INPUT_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:github\.event\.)?inputs(?:\.([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['"]([^'"]+)['"]\s*\])"#,
    )
    .expect("GitHub Actions input expression regex must compile")
});
static METADATA_FETCH_ARGUMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:--depth=[0-9]+ )?origin [A-Za-z0-9_$}{/.-]+$")
        .expect("Git metadata fetch argument regex must compile")
});

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn reports_untrusted_expressions_once_per_run_command() {
        let findings = analyze_auxiliary([(
            ".github/workflows/release.yml",
            r#"name: release
jobs:
  publish:
    steps:
      - run: echo "${{ inputs.version }}"
      - run: |
          echo "${{ github.event.pull_request.title }}"
          echo "${{ inputs.channel }}"
      - run: echo '${{ github.head_ref }}'
"#,
        )]);

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![5, 7, 9]
        );
    }

    #[test]
    fn accepts_guaranteed_numeric_and_hash_event_values() {
        let findings = analyze_auxiliary([(
            ".github/workflows/cleanup.yml",
            r#"jobs:
  cleanup:
    steps:
      - run: gh pr edit "${{ github.event.pull_request.number }}"
      - run: gh api -f sha="${{ github.event.workflow_run.head_sha }}"
      - run: echo "${{ github.event.pull_request.title }}"
"#,
        )]);

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [6]
        );
    }

    #[test]
    fn accepts_only_complete_base_repository_default_branch_expressions() {
        let path = ".github/workflows/labels.yml";
        let findings = analyze_auxiliary([(
            path,
            r#"jobs:
  labels:
    steps:
      - run: git fetch origin ${{ github.event.repository.default_branch }}
      - run: |
          git diff origin/${{github.event.repository.default_branch}} --name-only
      - run: echo "${{ github.event.pull_request.head.repo.default_branch }}"
      - run: echo "${{ github.event.repository.default_branch_suffix }}"
      - run: echo "${{ github.event.repository.default_branch.name }}"
      - run: echo "${{ github.event.repository.default_branch || github.event.pull_request.title }}"
      - run: echo "${{ github.event.repository.default_branch }} ${{ github.event.pull_request.body }}"
      - run: echo "${{ github.event.repository.default_branch }} ${{ github.head_ref }}"
      - run: echo "${{ github.event.repository.default_branch }} ${{ github.event.pull_request.title }}"
      - run: echo "${{ github.event.repository.default_branch }} ${{ github.event.repository.name }}"
      - run: echo "${{ github.event.repository.default_branch + 'suffix' }}"
      - run: |
          echo "${{ github.event.repository.default_branch }}"
          echo "${{ github.event.pull_request.body }}"
"#,
        )]);

        let injections = findings
            .iter()
            .filter(|finding| finding.code == TEMPLATE_INJECTION)
            .collect::<Vec<_>>();
        assert_eq!(
            injections
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [7, 8, 9, 10, 11, 12, 13, 14, 15, 18]
        );
        for finding in injections {
            assert_eq!(finding.path, path);
            assert_eq!(finding.confidence, "high");
            assert!(finding.related_files.is_empty());
        }
    }

    #[test]
    fn accepts_environment_indirection_and_trusted_expressions() {
        let findings = analyze_auxiliary([(
            ".github/workflows/release.yaml",
            r#"env:
  RELEASE_VERSION: ${{ inputs.version }}
jobs:
  publish:
    steps:
      - run: echo "$RELEASE_VERSION"
      - run: echo "${{ needs.verify.outputs.tag }}"
      - run: echo "${{ github.sha }}"
      - uses: owner/action@0123456789abcdef0123456789abcdef01234567
        with:
          message: ${{ github.event.issue.title }}
"#,
        )]);

        assert!(
            findings
                .iter()
                .all(|finding| finding.code != TEMPLATE_INJECTION),
            "unexpected findings: {findings:?}"
        );
    }

    #[test]
    fn accepts_boolean_and_number_inputs_but_keeps_choice_and_string_inputs() {
        let findings = analyze_auxiliary([(
            ".github/workflows/release.yml",
            r#"on:
  workflow_dispatch:
    inputs:
      dry_run:
        type: boolean
      channel:
        type: choice
        options: [stable, next]
      retries:
        type: number
      release_name:
        type: string
jobs:
  publish:
    steps:
      - run: echo "${{ inputs.dry_run }} ${{ inputs.retries }}"
      - run: echo "${{ inputs.channel }}"
      - run: echo "${{ inputs.release_name }}"
"#,
        )]);

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![17, 18]
        );
    }

    #[test]
    fn groups_mutable_external_references_per_workflow() {
        let findings = analyze_auxiliary([(
            ".github/workflows/ci.yml",
            r#"steps:
  - uses: actions/checkout@v5
  - uses: "owner/action@main"
  - uses: owner/action@0123456789abcdef0123456789abcdef01234567
  - uses: ./local-action
  - uses: docker://alpine:3.22
  - run: |
      cat <<'EOF'
      uses: owner/example@main
      EOF
"#,
        )]);
        let mutable = findings
            .iter()
            .filter(|finding| finding.code == MUTABLE_ACTION_REFERENCE)
            .collect::<Vec<_>>();

        assert_eq!(mutable.len(), 1);
        assert_eq!(mutable[0].line, 2);
        assert_eq!(
            mutable[0].message,
            "2 external action references in this workflow are not pinned to full commit SHAs"
        );
    }

    #[test]
    fn ignores_comments_non_workflow_yaml_and_nested_fixtures() {
        let findings = analyze_auxiliary([
            (
                ".github/workflows/ci.yml",
                "# run: echo '${{ inputs.value }}'\n# uses: owner/action@main\nname: ${{ inputs.value }}",
            ),
            (
                ".github/workflows/fixtures/unsafe.yml",
                "steps:\n  - run: echo '${{ inputs.value }}'\n  - uses: owner/action@main",
            ),
            (
                "config/release.yml",
                "run: echo '${{ inputs.value }}'\nuses: owner/action@main",
            ),
        ]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn reports_untrusted_checkout_executed_by_pull_request_target_job() {
        let findings = analyze_auxiliary([(
            ".github/workflows/review.yml",
            r#"on:
  pull_request_target:
jobs:
  inspect:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"#,
        )]);

        let risky = findings
            .iter()
            .filter(|finding| finding.code == PULL_REQUEST_TARGET_CHECKOUT)
            .collect::<Vec<_>>();
        assert_eq!(risky.len(), 1);
        assert_eq!(risky[0].line, 8);
    }

    #[test]
    fn accepts_base_checkout_non_privileged_trigger_and_nonexecuted_head() {
        let findings = analyze_auxiliary([
            (
                ".github/workflows/base.yml",
                r#"on: pull_request_target
jobs:
  inspect:
    steps:
      - uses: actions/checkout@v5
      - run: cargo test
"#,
            ),
            (
                ".github/workflows/pull-request.yml",
                r#"on: [pull_request]
jobs:
  inspect:
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.head_ref }}
      - run: cargo test
"#,
            ),
            (
                ".github/workflows/no-execution.yml",
                r#"on: pull_request_target
jobs:
  inspect:
    steps:
      - uses: actions/checkout@v5
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
"#,
            ),
        ]);

        assert!(
            findings
                .iter()
                .all(|finding| finding.code != PULL_REQUEST_TARGET_CHECKOUT),
            "unexpected findings: {findings:?}"
        );
    }

    #[test]
    fn accepts_event_numbers_and_commit_hashes_but_keeps_names_refs_and_mixed_expressions() {
        let path = ".github/workflows/ci.yml";
        let findings = analyze_auxiliary([(
            path,
            r#"jobs:
  inspect:
    steps:
      - run: echo ${{ github.event.number }}
      - run: git log -n 1 ${{github.event.after}}
      - run: git diff ${{ github.event.before }} HEAD
      - run: git fetch origin ${{ github.event.pull_request.base.sha }}
      - run: git show ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.head.ref }}"
      - run: echo "${{ github.event.pull_request.title }}"
      - run: echo "${{ format('{0}', github.event.pull_request.title) }}"
      - run: echo "${{ github.event.number || github.event.pull_request.title }}"
      - run: echo "${{ github.event.after }} ${{ github.head_ref }}"
      - run: echo "${{ github.event.number_suffix }}"
      - run: echo "${{ github.event.pull_request.head.repo.full_name }}"
"#,
        )]);
        let injections = findings
            .iter()
            .filter(|finding| finding.code == TEMPLATE_INJECTION)
            .collect::<Vec<_>>();
        assert_eq!(
            injections
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [9, 10, 11, 12, 13, 14, 15]
        );
        for finding in injections {
            assert_eq!(finding.path, path);
            assert_eq!(finding.confidence, "high");
        }
    }

    #[test]
    fn retains_untrusted_expressions_started_in_multiline_quoted_run_scalars() {
        let findings = analyze_auxiliary([(
            ".github/workflows/quoted.yml",
            r#"jobs:
  inspect:
    steps:
      - run: "echo '${{ github.event.pull_request.title
          }}'"
      - run: 'echo "${{ inputs.version
          }}"'
"#,
        )]);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [4, 6]
        );
    }

    #[test]
    fn handles_multiline_expressions_and_crlf_without_extending_into_sibling_env() {
        let source = r#"jobs:
  inspect:
    steps:
      - run: |
          echo "${{
            github.event.after
          }}"
        env:
          TITLE: ${{ github.event.pull_request.title }}
      - run: >-
          echo "${{
            github.event.number
            || github.event.pull_request.title
          }}"
          echo "${{ github.head_ref }}"
      - run: |
          echo "${{ github.event.pull_request.title
          }}"
"#;
        let crlf_source = source.replace('\n', "\r\n");
        for source in [source, crlf_source.as_str()] {
            let findings = analyze_auxiliary([(".github/workflows/multiline.yml", source)]);
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.code == TEMPLATE_INJECTION)
                    .map(|finding| finding.line)
                    .collect::<Vec<_>>(),
                [11, 17]
            );
        }
    }

    #[test]
    fn accepts_boolean_and_number_event_input_aliases_but_keeps_choice_and_mixed_expressions() {
        let findings = analyze_auxiliary([(
            ".github/workflows/promote.yml",
            r#"on:
  workflow_dispatch:
    inputs:
      kind:
        type: choice
        options: [rc, lts]
      count:
        type: number
      dry_run:
        type: boolean
      commitHash:
        type: string
jobs:
  release:
    steps:
      - run: echo "${{ github.event.inputs.kind }}"
      - run: echo "${{ github.event.inputs['kind'] }}"
      - run: echo "${{ inputs.dry_run }}"
      - run: echo "${{ github.event.inputs.count }}"
      - run: echo "${{ github.event.inputs.commitHash }}"
      - run: echo "${{ inputs.kind || github.event.inputs.commitHash }}"
      - run: echo "${{ format('{0}', github.event.pull_request.title) }}"
      - run: echo "${{ true && inputs.commitHash }}"
      - run: echo "${{ github.event.inputs.kind || github.head_ref }}"
"#,
        )]);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [16, 17, 20, 21, 22, 23, 24]
        );
    }

    #[test]
    fn reports_malicious_choice_options_and_mixed_choice_string_expressions() {
        let findings = analyze_auxiliary([(
            ".github/workflows/choice.yml",
            r#"on:
  workflow_dispatch:
    inputs:
      command:
        type: choice
        options:
          - safe
          - '$(./untrusted)'
      suffix:
        type: string
jobs:
  inspect:
    steps:
      - run: echo "${{ inputs.command }}"
      - run: echo "${{ github.event.inputs.command }}"
      - run: echo "${{ inputs.command || inputs.suffix }}"
      - run: echo "${{ inputs.suffix && github.event.inputs.command }}"
      - run: echo "${{ inputs.command == 'safe' && 'safe' || inputs.suffix }}"
"#,
        )]);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [14, 15, 16, 17, 18]
        );
    }

    #[test]
    fn does_not_infer_dispatch_types_from_unrelated_or_reusable_workflow_mappings() {
        let findings = analyze_auxiliary([(
            ".github/workflows/call.yml",
            r#"on:
  workflow_call:
    inputs:
      count:
        type: number
jobs:
  inspect:
    env:
      inputs:
        version:
          type: boolean
    steps:
      - run: echo "${{ inputs.count }}"
      - run: echo "${{ github.event.inputs.count }}"
      - run: echo "${{ inputs.version }}"
"#,
        )]);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [14, 15]
        );
    }

    #[test]
    fn respects_run_sibling_env_and_non_run_block_scalar_boundaries() {
        let findings = analyze_auxiliary([(
            ".github/workflows/blocks.yml",
            r#"env:
  EXAMPLE: |-
    run: echo "${{ inputs.example }}"
    uses: owner/example@main
jobs:
  inspect:
    steps:
      - run: |-
          echo ready
        env:
          TITLE: ${{ github.event.pull_request.title }}
      - name: Descriptive scalar
        env:
          DESCRIPTION: >-
            run: echo "${{ inputs.description }}"
            uses: owner/example@main
        run: echo ready
      - uses: owner/real-action@v1
      - run: >-
          echo "${{ github.event.pull_request.title }}"
          echo "${{ inputs.second }}"
"#,
        )]);
        let injections = findings
            .iter()
            .filter(|finding| finding.code == TEMPLATE_INJECTION)
            .collect::<Vec<_>>();
        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].line, 20);
        let mutable = findings
            .iter()
            .filter(|finding| finding.code == MUTABLE_ACTION_REFERENCE)
            .collect::<Vec<_>>();
        assert_eq!(mutable.len(), 1);
        assert_eq!(mutable[0].line, 18);
        assert_eq!(
            mutable[0].message,
            "1 external action reference in this workflow is not pinned to full commit SHAs"
        );
    }

    #[test]
    fn accepts_privileged_checkout_metadata_inspection_and_clean_replacement() {
        let prefix = r#"on: pull_request_target
jobs:
  inspect:
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{github.event.pull_request.head.sha}}
"#;
        for suffix in [
            r#"      - name: Get changes
        shell: bash {0}
        run: |
          git fetch --depth=1 origin $BASE_SHA
          git diff --exit-code $BASE_SHA $HEAD_SHA -- ./release-notes
          echo "found_changes=$?" >> $GITHUB_OUTPUT
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
"#,
            r#"      - uses: actions/checkout@v5
      - run: cargo test
"#,
            r#"      - run: 'git diff --quiet HEAD -- ./release-notes'
"#,
        ] {
            let source = format!("{prefix}{suffix}");
            let findings = analyze_auxiliary([(".github/workflows/inspect.yml", &source)]);
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.code != PULL_REQUEST_TARGET_CHECKOUT),
                "unexpected checkout execution for {suffix}: {findings:?}"
            );
        }
        let findings = analyze_auxiliary([(
            ".github/workflows/order.yml",
            r#"on: pull_request_target
jobs:
  inspect:
    steps:
      - run: cargo test
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.head_ref }}
"#,
        )]);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != PULL_REQUEST_TARGET_CHECKOUT),
            "execution before the checkout is not execution of that checkout: {findings:?}"
        );
    }

    #[test]
    fn keeps_privileged_source_execution_and_unsafe_shell_construction_reportable() {
        let prefix = r#"on: pull_request_target
jobs:
  inspect:
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{github.event.pull_request.head.sha}}
"#;
        for suffix in [
            "      - run: cargo test\n",
            "      - uses: ./.github/actions/review\n",
            "      - run: echo \"$(./checked-out-script)\"\n",
            "      - run: echo \"${VALUE@P}\"\n",
            "      - run: git diff --ext-diff HEAD\n",
            "      - run: git fetch --upload-pack=./script origin HEAD\n",
            "      - shell: ./.github/custom-shell {0}\n        run: git diff --quiet HEAD\n",
            "      - run: git diff --quiet HEAD\n        env:\n          GIT_EXTERNAL_DIFF: ./script\n",
            "      - run: git diff --quiet HEAD\n        env:\n          BASH_ENV: ./script\n",
            "      - run: |\n          git diff --quiet HEAD\n          ./script\n",
            "      - uses: actions/checkout@v5\n        if: success()\n      - run: cargo test\n",
            "      - uses: actions/checkout@v5\n        with:\n          path: trusted\n      - run: cargo test\n",
            "      - uses: actions/checkout@v5\n        with:\n          clean: false\n      - run: cargo test\n",
        ] {
            let source = format!("{prefix}{suffix}");
            let findings = analyze_auxiliary([(".github/workflows/review.yml", &source)]);
            let risky = findings
                .iter()
                .filter(|finding| finding.code == PULL_REQUEST_TARGET_CHECKOUT)
                .collect::<Vec<_>>();
            assert_eq!(
                risky.len(),
                1,
                "lost checkout execution for {suffix}: {findings:?}"
            );
            assert_eq!(risky[0].path, ".github/workflows/review.yml");
            assert_eq!(risky[0].line, 5);
            assert_eq!(risky[0].confidence, "high");
        }
    }

    fn analyze_auxiliary<const N: usize>(files: [(&str, &str); N]) -> Vec<Finding> {
        let auxiliary = files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect();
        let sources = BTreeMap::new();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        analyze(&context)
    }
}
