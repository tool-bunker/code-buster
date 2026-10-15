use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use toml::Value;

use crate::discovery;
use crate::findings::{Finding, Severity};
use crate::rule_catalog;
use crate::source_analysis_context::SourceAnalysisContext;

mod public_api;
mod workspace;

pub(super) struct CargoManifest<'a> {
    pub(super) path: &'a str,
    pub(super) source: &'a str,
    pub(super) value: Value,
}

pub fn analyze(context: &SourceAnalysisContext<'_>) -> Vec<Finding> {
    let manifests = parse_manifests(context);
    let mut findings = Vec::new();
    for manifest in &manifests {
        append_dependency_findings(
            manifest.path,
            manifest.source,
            &manifest.value,
            &mut findings,
        );
        append_manifest_policy_findings(
            context,
            manifest.path,
            manifest.source,
            &manifest.value,
            &mut findings,
        );
    }
    append_project_policy_findings(context, &mut findings);
    findings.extend(workspace::analyze(context, &manifests));
    findings.extend(public_api::analyze(context, &manifests));
    findings
}

fn parse_manifests<'a>(context: &'a SourceAnalysisContext<'_>) -> Vec<CargoManifest<'a>> {
    context
        .auxiliary_files()
        .iter()
        .filter(|(path, _)| {
            path.ends_with("Cargo.toml")
                && !path.starts_with("@base/")
                && discovery::is_builtin_production_path(path)
        })
        .filter_map(|(path, source)| {
            toml::from_str::<Value>(source)
                .ok()
                .map(|value| CargoManifest {
                    path,
                    source,
                    value,
                })
        })
        .collect()
}

fn append_dependency_findings(
    path: &str,
    source: &str,
    manifest: &Value,
    findings: &mut Vec<Finding>,
) {
    let mut unpinned = BTreeSet::new();
    collect_unpinned_dependencies(manifest, &mut unpinned);
    let mut reported = BTreeSet::new();
    for dependency in DEPENDENCY_LINE.captures_iter(source) {
        let name = dependency.get(1).unwrap().as_str();
        if !unpinned.contains(name) || !reported.insert(name.to_owned()) {
            continue;
        }
        findings.push(finding(
            "rust-unpinned-git-dependency",
            path,
            line_at(source, dependency.get(0).unwrap().start()),
            format!("Git dependency {name} is not pinned with an immutable rev"),
        ));
    }

    let mut wildcard = BTreeSet::new();
    collect_wildcard_dependencies(manifest, &mut wildcard);
    for dependency in WILDCARD_DEPENDENCY_LINE.captures_iter(source) {
        let name = dependency.get(1).unwrap().as_str();
        if !wildcard.remove(name) {
            continue;
        }
        findings.push(finding(
            "rust-wildcard-dependency-version",
            path,
            line_at(source, dependency.get(0).unwrap().start()),
            format!("dependency {name} accepts every registry version"),
        ));
    }
}

fn append_manifest_policy_findings(
    context: &SourceAnalysisContext<'_>,
    path: &str,
    source: &str,
    manifest: &Value,
    findings: &mut Vec<Finding>,
) {
    let Some(package) = manifest.get("package").and_then(Value::as_table) else {
        return;
    };
    let line = section_line(source, "package");
    if !package.contains_key("rust-version") && !requires_unstable_cargo_features(manifest) {
        findings.push(finding(
            "rust-missing-rust-version",
            path,
            line,
            "Cargo package does not declare its minimum supported Rust version".to_owned(),
        ));
    }
    if package_has_binary_target(context, path, manifest) && !has_applicable_lockfile(context, path)
    {
        findings.push(finding(
            "rust-binary-without-lockfile",
            path,
            line,
            "Cargo binary package has no committed lockfile".to_owned(),
        ));
    }
}

fn requires_unstable_cargo_features(manifest: &Value) -> bool {
    manifest
        .get("cargo-features")
        .and_then(Value::as_array)
        .is_some_and(|features| !features.is_empty())
}

fn append_project_policy_findings(
    context: &SourceAnalysisContext<'_>,
    findings: &mut Vec<Finding>,
) {
    if !has_auxiliary(context, "Cargo.toml") {
        return;
    }
    let evidence = ci_policy_evidence(context);
    let Some((path, line)) = evidence.first_rust_command else {
        return;
    };
    if !evidence.has_clippy {
        findings.push(finding(
            "rust-missing-clippy-ci",
            path,
            line,
            "Rust CI runs Cargo build, check, or test commands without running Clippy".to_owned(),
        ));
    }
    if !evidence.has_checked_format {
        findings.push(finding(
            "rust-missing-format-ci",
            path,
            line,
            "Rust CI runs Cargo commands without checking rustfmt output".to_owned(),
        ));
    }
    if has_auxiliary(context, "Cargo.lock") {
        if !evidence.has_audit {
            findings.push(finding(
                "rust-missing-dependency-audit",
                path,
                line,
                "Rust CI runs Cargo build, check, or test commands without a dependency audit"
                    .to_owned(),
            ));
        }
        for (path, line) in evidence.unlocked_commands {
            findings.push(finding(
                "rust-unlocked-ci-command",
                path,
                line,
                "Cargo CI command can re-resolve dependencies without --locked or --frozen"
                    .to_owned(),
            ));
        }
    }
}

fn has_auxiliary(context: &SourceAnalysisContext<'_>, name: &str) -> bool {
    context
        .auxiliary_files()
        .keys()
        .any(|path| !path.starts_with("@base/") && is_named_path(path, name))
}

#[derive(Default)]
struct CiPolicyEvidence<'a> {
    first_rust_command: Option<(&'a str, usize)>,
    unlocked_commands: Vec<(&'a str, usize)>,
    has_clippy: bool,
    has_checked_format: bool,
    has_audit: bool,
}

impl<'a> CiPolicyEvidence<'a> {
    fn observe(&mut self, path: &'a str, line_index: usize, raw_line: &str) {
        let line = ci_line_without_comment(raw_line);
        if self.first_rust_command.is_none() && CARGO_RUST_COMMAND.is_match(line) {
            self.first_rust_command = Some((path, line_index + 1));
        }
        self.has_clippy |= CARGO_CLIPPY_COMMAND.is_match(line);
        self.has_checked_format |=
            CARGO_CHECKED_FORMAT.is_match(line) || DIRECT_RUSTFMT_CHECK.is_match(line);
        self.has_audit |= CARGO_AUDIT_COMMAND.is_match(line) || AUDIT_ACTION.is_match(line);
        if !self
            .unlocked_commands
            .iter()
            .any(|(reported_path, _)| *reported_path == path)
            && CARGO_LOCKFILE_COMMAND
                .find_iter(line)
                .any(|command| !CARGO_LOCK_FLAG.is_match(command.as_str()))
        {
            self.unlocked_commands.push((path, line_index + 1));
        }
    }
}

fn ci_policy_evidence<'context>(
    context: &'context SourceAnalysisContext<'_>,
) -> CiPolicyEvidence<'context> {
    let mut evidence = CiPolicyEvidence::default();
    for (path, source) in context
        .auxiliary_files()
        .iter()
        .filter(|(path, _)| is_ci_path(path))
    {
        for (line_index, raw_line) in source.lines().enumerate() {
            evidence.observe(path, line_index, raw_line);
        }
    }
    evidence
}

fn is_named_path(path: &str, name: &str) -> bool {
    path == name
        || path
            .strip_suffix(name)
            .is_some_and(|prefix| prefix.ends_with('/'))
}

pub(super) fn is_ci_path(path: &str) -> bool {
    matches!(
        path,
        ".gitlab-ci.yml" | "azure-pipelines.yml" | "Jenkinsfile"
    ) || path.strip_prefix(".github/workflows/").is_some_and(|name| {
        !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
    })
}

pub(super) fn ci_line_without_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

fn collect_unpinned_dependencies(value: &Value, result: &mut BTreeSet<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, value) in table {
        if ["dependencies", "dev-dependencies", "build-dependencies"].contains(&key.as_str()) {
            let Some(dependencies) = value.as_table() else {
                continue;
            };
            for (name, specification) in dependencies {
                let Some(specification) = specification.as_table() else {
                    continue;
                };
                if specification.get("git").and_then(Value::as_str).is_some()
                    && specification
                        .get("rev")
                        .and_then(Value::as_str)
                        .is_none_or(|revision| revision.trim().is_empty())
                {
                    result.insert(name.clone());
                }
            }
        } else {
            collect_unpinned_dependencies(value, result);
        }
    }
}

fn collect_wildcard_dependencies(value: &Value, result: &mut BTreeSet<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, value) in table {
        if ["dependencies", "dev-dependencies", "build-dependencies"].contains(&key.as_str()) {
            let Some(dependencies) = value.as_table() else {
                continue;
            };
            for (name, specification) in dependencies {
                if wildcard_registry_dependency(specification) {
                    result.insert(name.clone());
                }
            }
        } else {
            collect_wildcard_dependencies(value, result);
        }
    }
}

fn wildcard_registry_dependency(specification: &Value) -> bool {
    if specification.as_str() == Some("*") {
        return true;
    }
    let Some(table) = specification.as_table() else {
        return false;
    };
    table.get("version").and_then(Value::as_str) == Some("*")
        && !table.contains_key("path")
        && !table.contains_key("git")
        && table.get("workspace").and_then(Value::as_bool) != Some(true)
}

pub(super) fn section_line(source: &str, section: &str) -> usize {
    source
        .lines()
        .position(|line| {
            line.trim()
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
                == Some(section)
        })
        .map_or(1, |index| index + 1)
}

fn package_has_binary_target(
    context: &SourceAnalysisContext<'_>,
    manifest_path: &str,
    manifest: &Value,
) -> bool {
    let explicit_binary = manifest
        .get("bin")
        .and_then(Value::as_array)
        .is_some_and(|targets| !targets.is_empty());
    explicit_binary
        || context
            .sources()
            .keys()
            .any(|path| is_default_binary_source(path, manifest_path))
}

fn is_default_binary_source(source_path: &str, manifest_path: &str) -> bool {
    let directory = manifest_directory(manifest_path);
    if directory.is_empty() {
        return source_path == "src/main.rs";
    }
    source_path
        .strip_prefix(directory)
        .and_then(|path| path.strip_prefix('/'))
        == Some("src/main.rs")
}

fn has_applicable_lockfile(context: &SourceAnalysisContext<'_>, manifest_path: &str) -> bool {
    let package_directory = manifest_directory(manifest_path);
    context.auxiliary_files().keys().any(|path| {
        !path.starts_with("@base/")
            && path.strip_suffix("Cargo.lock").is_some_and(|prefix| {
                let lock_directory = prefix.strip_suffix('/').unwrap_or(prefix);
                lock_directory.is_empty()
                    || package_directory == lock_directory
                    || package_directory
                        .strip_prefix(lock_directory)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    })
}

pub(super) fn manifest_directory(path: &str) -> &str {
    path.strip_suffix("/Cargo.toml").unwrap_or_default()
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

pub(super) fn finding(code: &str, path: &str, line: usize, message: String) -> Finding {
    let metadata = rule_catalog::metadata(code).expect("Cargo rule metadata must exist");
    Finding {
        code: metadata.id.to_owned(),
        severity: Severity::parse(metadata.default_severity)
            .expect("Cargo rule severity must be valid"),
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

static DEPENDENCY_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^\n]*\bgit\s*=").unwrap());
static WILDCARD_DEPENDENCY_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^\s*([A-Za-z0-9_-]+)\s*=\s*(?:"\*"|'\*'|\{[^\n}]*\bversion\s*=\s*["']\*["'][^\n}]*\})"#,
    )
    .unwrap()
});
static CARGO_RUST_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(?:^\s*(?:(?:-\s+)?(?:run|script)\s*:\s*|-\s+|sh\s+(?:-[A-Z]+\s+)?["']?)?|[;&|]\s*)["']?cargo\s+(?:\+\S+\s+)?(?:build|check|test)\b"#,
    )
    .unwrap()
});
static CARGO_CLIPPY_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(?:^\s*(?:(?:-\s+)?(?:run|script)\s*:\s*|-\s+|sh\s+(?:-[A-Z]+\s+)?["']?)?|[;&|]\s*)["']?cargo\s+(?:\+\S+\s+)?clippy\b"#,
    )
    .unwrap()
});
static CARGO_CHECKED_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(?:^\s*(?:(?:-\s+)?(?:run|script)\s*:\s*|-\s+|sh\s+(?:-[A-Z]+\s+)?["']?)?|[;&|]\s*)["']?cargo\s+(?:\+\S+\s+)?fmt\b[^;&|]*--check\b"#,
    )
    .unwrap()
});
static DIRECT_RUSTFMT_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(?:^\s*(?:-\s+)?(?:if\s+!\s+)?|[;&|]\s*)["']?rustfmt\b[^;&|]*--check\b"#)
        .unwrap()
});
static CARGO_LOCKFILE_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(?:^\s*(?:(?:-\s+)?(?:run|script)\s*:\s*|-\s+|sh\s+(?:-[A-Z]+\s+)?["']?)?|[;&|]\s*)["']?cargo\s+(?:\+\S+\s+)?(?:build|check|test|clippy)\b[^;&|]*"#,
    )
    .unwrap()
});
static CARGO_LOCK_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)--(?:locked|frozen)\b").unwrap());
static CARGO_AUDIT_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(?:^\s*(?:(?:-\s+)?(?:run|script)\s*:\s*|-\s+|sh\s+(?:-[A-Z]+\s+)?["']?)?|[;&|]\s*)["']?cargo\s+(?:\+\S+\s+)?(?:audit\b|deny\s+check\b)"#,
    )
    .unwrap()
});
static AUDIT_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)^\s*(?:-\s+)?uses\s*:\s*["']?(?:rustsec/audit-check|[A-Z0-9_.-]+/cargo-deny-action)@"#,
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn reports_git_dependencies_without_immutable_revisions() {
        let manifest = "[dependencies]\nmovable = { git = \"https://example.com/movable.git\", branch = \"main\" }\npinned = { git = \"https://example.com/pinned.git\", rev = \"0123456789abcdef\" }\nregistry = \"1.2.3\"\n\n[build-dependencies]\nbuild-helper = { git = \"https://example.com/build.git\", tag = \"v1\" }\n\n[target.'cfg(unix)'.dependencies]\ntarget-helper = { git = \"https://example.com/target.git\" }";
        let auxiliary = BTreeMap::from([("Cargo.toml".to_owned(), manifest.to_owned())]);
        let sources = BTreeMap::new();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        let findings = analyze(&context);

        assert_eq!(
            findings
                .iter()
                .map(|finding| format!("{}:{}", finding.message, finding.line))
                .collect::<Vec<_>>(),
            vec![
                "Git dependency movable is not pinned with an immutable rev:2",
                "Git dependency build-helper is not pinned with an immutable rev:7",
                "Git dependency target-helper is not pinned with an immutable rev:10",
            ]
        );
    }

    #[test]
    fn ignores_malformed_manifests_and_non_git_workspace_inheritance() {
        let auxiliary = BTreeMap::from([
            (
                "member/Cargo.toml".to_owned(),
                "[dependencies]\nshared = { workspace = true }\nlocal = { path = \"../local\" }"
                    .to_owned(),
            ),
            ("broken/Cargo.toml".to_owned(), "[dependencies".to_owned()),
        ]);
        let sources = BTreeMap::new();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);

        assert!(analyze(&context).is_empty());
    }
    #[test]
    fn appends_missing_ci_policies_after_dependency_findings() {
        let findings = analyze_auxiliary([
            (
                "Cargo.toml",
                "[dependencies]\nmovable = { git = \"https://example.com/movable.git\" }",
            ),
            ("Cargo.lock", "version = 4"),
            (
                ".github/workflows/ci.yml",
                "name: CI\nsteps:\n  # cargo clippy && cargo audit\n  - run: cargo +stable test\n  - run: echo \"cargo clippy\"\n  # run: cargo audit",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.code.as_str(),
                    finding.path.as_str(),
                    finding.line,
                    finding.message.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "rust-unpinned-git-dependency",
                    "Cargo.toml",
                    2,
                    "Git dependency movable is not pinned with an immutable rev",
                ),
                (
                    "rust-missing-clippy-ci",
                    ".github/workflows/ci.yml",
                    4,
                    "Rust CI runs Cargo build, check, or test commands without running Clippy",
                ),
                (
                    "rust-missing-format-ci",
                    ".github/workflows/ci.yml",
                    4,
                    "Rust CI runs Cargo commands without checking rustfmt output",
                ),
                (
                    "rust-missing-dependency-audit",
                    ".github/workflows/ci.yml",
                    4,
                    "Rust CI runs Cargo build, check, or test commands without a dependency audit",
                ),
                (
                    "rust-unlocked-ci-command",
                    ".github/workflows/ci.yml",
                    4,
                    "Cargo CI command can re-resolve dependencies without --locked or --frozen",
                ),
            ]
        );
    }

    #[test]
    fn accepts_clippy_and_all_supported_dependency_audits() {
        let audit_evidence = [
            "  - run: cargo audit",
            "  - run: cargo +nightly audit",
            "  - run: cargo deny check",
            "  - run: cargo deny check advisories",
            "  - uses: rustsec/audit-check@v2",
            "  - uses: EmbarkStudios/cargo-deny-action@v2",
        ];

        for evidence in audit_evidence {
            let workflow = format!(
                "steps:\n  - run: cargo +stable check --locked\n  - run: cargo +stable clippy --frozen\n  - run: cargo fmt --all -- --check\n{evidence}"
            );
            let findings = analyze_auxiliary([
                (
                    "Cargo.toml",
                    "[package]\nname = \"app\"\nrust-version = \"1.85\"",
                ),
                ("Cargo.lock", "version = 4"),
                (".github/workflows/ci.yaml", workflow.as_str()),
            ]);
            assert!(findings.is_empty(), "unexpected finding for {evidence}");
        }
    }

    #[test]
    fn ignores_absent_external_and_base_only_ci_projects() {
        let external_only = analyze_auxiliary([
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nrust-version = \"1.85\"",
            ),
            ("Cargo.lock", "version = 4"),
            (".circleci/config.yml", "steps:\n  - run: cargo test"),
            ("notes.yaml", "run: cargo test"),
        ]);
        assert!(external_only.is_empty());

        let base_only = analyze_auxiliary([
            ("@base/Cargo.toml", "[package]\nname = \"old\""),
            ("@base/Cargo.lock", "version = 4"),
            (".gitlab-ci.yml", "test:\n  script: cargo test"),
        ]);
        assert!(base_only.is_empty());
    }

    #[test]
    fn exempts_projects_without_a_lockfile_from_dependency_audit() {
        let findings = analyze_auxiliary([
            (
                "member/Cargo.toml",
                "[package]\nname = \"member\"\nrust-version = \"1.85\"",
            ),
            (
                "azure-pipelines.yml",
                "steps:\n  - script: cargo fmt --all -- --check\n  - script: cargo build --locked",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec!["rust-missing-clippy-ci"]
        );
    }

    #[test]
    fn comments_and_descriptive_strings_do_not_satisfy_ci_policies() {
        let findings = analyze_auxiliary([
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nrust-version = \"1.85\"",
            ),
            ("Cargo.lock", "version = 4"),
            (
                "Jenkinsfile",
                "# cargo test\nname: \"run: cargo clippy\"\nsh 'cargo test --locked' # cargo clippy && cargo audit\nsh 'echo \"run: cargo clippy\"'\n// uses: rustsec/audit-check@v2",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec![
                "rust-missing-clippy-ci",
                "rust-missing-format-ci",
                "rust-missing-dependency-audit",
            ]
        );
    }

    #[test]
    fn reports_manifest_reproducibility_gaps_in_source_order() {
        let findings = analyze_project(
            [(
                "Cargo.toml",
                "[package]\nname = \"app\"\n\n[dependencies]\nopen = \"*\"\ninline = { version = \"*\" }\nlocal = { version = \"*\", path = \"../local\" }\ninherited = { workspace = true }\n\n[target.'cfg(unix)'.dependencies]\ntarget-open = \"*\"",
            )],
            [("src/main.rs", "fn main() {}")],
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("rust-wildcard-dependency-version", 5),
                ("rust-wildcard-dependency-version", 6),
                ("rust-wildcard-dependency-version", 11),
                ("rust-missing-rust-version", 1),
                ("rust-binary-without-lockfile", 1),
            ]
        );
    }

    #[test]
    fn accepts_workspace_msrv_lockfile_and_constrained_dependencies() {
        let findings = analyze_project(
            [
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"member\"]\n\n[workspace.package]\nrust-version = \"1.85\"\n\n[workspace.dependencies]\nserde = \"1\"",
                ),
                (
                    "member/Cargo.toml",
                    "[package]\nname = \"member\"\nrust-version.workspace = true\n\n[dependencies]\nserde.workspace = true",
                ),
                ("Cargo.lock", "version = 4"),
            ],
            [("member/src/main.rs", "fn main() {}")],
        );

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn reports_unlocked_ci_once_per_file_and_missing_format_gate() {
        let findings = analyze_auxiliary([
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nrust-version = \"1.85\"",
            ),
            ("Cargo.lock", "version = 4"),
            (
                ".github/workflows/ci.yml",
                "steps:\n  - run: cargo test\n  - run: cargo clippy --locked\n  - run: cargo audit\n  - run: cargo check",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("rust-missing-format-ci", 2),
                ("rust-unlocked-ci-command", 2),
            ]
        );
    }

    #[test]
    fn accepts_frozen_commands_and_checked_rustfmt() {
        let findings = analyze_auxiliary([
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nrust-version = \"1.85\"",
            ),
            ("Cargo.lock", "version = 4"),
            (
                ".gitlab-ci.yml",
                "script:\n  - cargo test --frozen\n  - cargo clippy --locked\n  - if ! rustfmt --check --edition 2021 src/lib.rs; then exit 1; fi\n  - cargo deny check",
            ),
        ]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn ignores_non_production_manifests() {
        let findings = analyze_project(
            [
                (
                    "tests-integration/Cargo.toml",
                    "[package]\nname = \"tests\"\n\n[dependencies]\nanything = \"*\"\n\n[[bin]]\nname = \"fixture\"",
                ),
                (
                    "fuzz/Cargo.toml",
                    "[package]\nname = \"fuzz\"\n\n[package.metadata]\ncargo-fuzz = true\n\n[[bin]]\nname = \"target\"",
                ),
                (
                    "examples/Cargo.toml",
                    "[package]\nname = \"examples\"\n\n[dependencies]\nanything = \"*\"",
                ),
                (
                    "benches/Cargo.toml",
                    "[package]\nname = \"benches\"\n\n[dependencies]\nanything = \"*\"",
                ),
            ],
            [
                ("tests-integration/src/main.rs", "fn main() {}"),
                ("fuzz/src/main.rs", "fn main() {}"),
            ],
        );

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn accepts_nightly_manifest_features_without_a_stable_msrv() {
        let findings = analyze_auxiliary([(
            "Cargo.toml",
            "cargo-features = [\"panic-immediate-abort\"]\n\n[package]\nname = \"nightly-only\"",
        )]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    fn analyze_project<const A: usize, const S: usize>(
        files: [(&str, &str); A],
        source_files: [(&str, &str); S],
    ) -> Vec<Finding> {
        let auxiliary = files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect();
        let sources = source_files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        analyze(&context)
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
