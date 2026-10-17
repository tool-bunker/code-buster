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
        findings.extend(template_injections(path, source));
        if let Some(finding) = mutable_action_references(path, source) {
            findings.push(finding);
        }
        if workflow_uses_pull_request_target(source) {
            findings.extend(pull_request_target_checkouts(path, source));
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
    reported: bool,
}

// code-buster-ignore complex-function: YAML run-block tracking keeps indentation and report state in one pass.
fn template_injections(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let safe_inputs = typed_safe_inputs(source);
    let mut block: Option<RunBlock> = None;

    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if let Some(active) = block.as_mut() {
            if line.trim().is_empty() {
                continue;
            }
            if indentation(line) > active.indentation {
                if !active.reported && contains_untrusted_expression(line, &safe_inputs) {
                    findings.push(finding(
                        TEMPLATE_INJECTION,
                        path,
                        line_number,
                        "Untrusted GitHub Actions data is interpolated directly into a shell command"
                            .to_owned(),
                    ));
                    active.reported = true;
                }
                continue;
            }
            block = None;
        }

        let Some(value) = yaml_value(line, "run") else {
            continue;
        };
        if is_block_scalar(value) {
            block = Some(RunBlock {
                indentation: indentation(line),
                reported: false,
            });
        } else if contains_untrusted_expression(value, &safe_inputs) {
            findings.push(finding(
                TEMPLATE_INJECTION,
                path,
                line_number,
                "Untrusted GitHub Actions data is interpolated directly into a shell command"
                    .to_owned(),
            ));
        }
    }

    findings
}

fn mutable_action_references(path: &str, source: &str) -> Option<Finding> {
    let mut run_block_indentation = None;
    let mut mutable = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if let Some(active_indentation) = run_block_indentation {
            if line.trim().is_empty() || indentation(line) > active_indentation {
                continue;
            }
            run_block_indentation = None;
        }
        if yaml_value(line, "run").is_some_and(is_block_scalar) {
            run_block_indentation = Some(indentation(line));
            continue;
        }
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

fn contains_untrusted_expression(value: &str, safe_inputs: &BTreeSet<String>) -> bool {
    UNTRUSTED_EVENT_EXPRESSION.is_match(value)
        || INPUT_EXPRESSION.captures_iter(value).any(|capture| {
            capture
                .get(1)
                .or_else(|| capture.get(2))
                .is_some_and(|name| !safe_inputs.contains(name.as_str()))
        })
}

fn typed_safe_inputs(source: &str) -> BTreeSet<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut safe = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(kind) = yaml_value(line, "type").and_then(scalar_value) else {
            continue;
        };
        if !matches!(kind, "boolean" | "choice" | "number") {
            continue;
        }
        let Some((input_index, input_indent, input)) =
            parent_mapping(&lines, index, indentation(line))
        else {
            continue;
        };
        let Some((_, _, parent)) = parent_mapping(&lines, input_index, input_indent) else {
            continue;
        };
        if parent == "inputs" {
            safe.insert(input.to_owned());
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
fn workflow_uses_pull_request_target(source: &str) -> bool {
    let lines = source.lines().collect::<Vec<_>>();
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

fn pull_request_target_checkouts(path: &str, source: &str) -> Vec<Finding> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut findings = Vec::new();
    for (start, end) in job_ranges(&lines) {
        for index in start..end {
            let Some(action) = yaml_value(lines[index], "uses").and_then(scalar_value) else {
                continue;
            };
            if !action.starts_with("actions/checkout@") {
                continue;
            }
            let step_end = step_end(&lines, index, end);
            if checkout_uses_untrusted_head(&lines[index + 1..step_end])
                && job_executes_checkout(&lines[step_end..end])
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
                value.contains("${{ github.event.pull_request.head.")
                    || value.contains("${{ github.head_ref")
            })
        })
    })
}

fn job_executes_checkout(lines: &[&str]) -> bool {
    lines.iter().any(|line| {
        yaml_value(line, "run").is_some()
            || yaml_value(line, "uses")
                .and_then(scalar_value)
                .is_some_and(|action| action.starts_with("./"))
    })
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

static UNTRUSTED_EVENT_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\{\s*(?:github\.event(?:\.|\[)|github\.head_ref\b)")
        .expect("GitHub Actions event expression regex must compile")
});
static INPUT_EXPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\{\{\s*inputs(?:\.([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['"]([^'"]+)['"]\s*\])"#)
        .expect("GitHub Actions input expression regex must compile")
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
    fn accepts_typed_non_string_workflow_inputs_in_shell_commands() {
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
      - run: echo "${{ inputs.dry_run }} ${{ inputs.channel }} ${{ inputs.retries }}"
      - run: echo "${{ inputs.release_name }}"
"#,
        )]);

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == TEMPLATE_INJECTION)
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![17]
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
