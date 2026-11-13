use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use semver::{Op, VersionReq};
use toml::Value;

use crate::findings::Finding;
use crate::source_analysis_context::SourceAnalysisContext;

use super::{
    CargoManifest, ci_line_without_comment, finding, for_each_ci_command_line, is_ci_path,
    is_sourcehut_path, manifest_directory, section_line,
};

pub(super) fn analyze(
    context: &SourceAnalysisContext<'_>,
    manifests: &[CargoManifest<'_>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for workspace in discover_workspaces(manifests) {
        append_missing_resolver(&workspace, &mut findings);
        append_ignored_member_sections(&workspace, &mut findings);
        append_partial_workspace_ci(context, &workspace, &mut findings);
        append_dependency_policy(&workspace, &mut findings);
        append_redundant_member_lockfiles(context, &workspace, &mut findings);
    }
    findings
}

struct Workspace<'a> {
    root: &'a CargoManifest<'a>,
    members: Vec<&'a CargoManifest<'a>>,
}

fn discover_workspaces<'a>(manifests: &'a [CargoManifest<'a>]) -> Vec<Workspace<'a>> {
    manifests
        .iter()
        .filter(|manifest| manifest.value.get("workspace").is_some())
        .map(|root| Workspace {
            root,
            members: manifests
                .iter()
                .filter(|candidate| is_workspace_member(root, candidate))
                .collect(),
        })
        .collect()
}

pub(super) fn owning_workspace<'a>(
    candidate: &CargoManifest<'_>,
    manifests: &'a [CargoManifest<'_>],
) -> Option<&'a CargoManifest<'a>> {
    if candidate.value.get("package")?.get("workspace").is_some() {
        return None;
    }
    let root = manifests
        .iter()
        .filter(|manifest| manifest.value.get("workspace").is_some())
        .filter(|manifest| {
            manifest.path == candidate.path
                || relative_manifest_directory(manifest.path, candidate.path).is_some()
        })
        .max_by_key(|manifest| manifest.path.len())?;
    is_workspace_member(root, candidate).then_some(root)
}

fn is_workspace_member(root: &CargoManifest<'_>, candidate: &CargoManifest<'_>) -> bool {
    if candidate.value.get("package").is_none() {
        return false;
    }
    if candidate.path == root.path {
        return true;
    }
    if candidate.value.get("workspace").is_some() {
        return false;
    }
    let Some(relative) = relative_manifest_directory(root.path, candidate.path) else {
        return false;
    };
    let Some(workspace) = root.value.get("workspace").and_then(Value::as_table) else {
        return false;
    };
    let included = workspace
        .get("members")
        .and_then(Value::as_array)
        .is_some_and(|members| matches_any_member(members, relative));
    included
        && !workspace
            .get("exclude")
            .and_then(Value::as_array)
            .is_some_and(|excludes| matches_any_member(excludes, relative))
}

fn relative_manifest_directory<'a>(root_path: &str, member_path: &'a str) -> Option<&'a str> {
    let root = manifest_directory(root_path);
    let member = manifest_directory(member_path);
    if root.is_empty() {
        return (!member.is_empty()).then_some(member);
    }
    member
        .strip_prefix(root)
        .and_then(|relative| relative.strip_prefix('/'))
        .filter(|relative| !relative.is_empty())
}

fn matches_any_member(patterns: &[Value], relative: &str) -> bool {
    patterns.iter().any(|pattern| {
        pattern
            .as_str()
            .is_some_and(|pattern| member_pattern_matches(pattern, relative))
    })
}

fn member_pattern_matches(pattern: &str, relative: &str) -> bool {
    path_segments_match(
        normalize_member_pattern(pattern),
        relative.trim_matches('/'),
    )
}

fn normalize_member_pattern(pattern: &str) -> &str {
    pattern
        .trim()
        .trim_start_matches("./")
        .trim_end_matches("/Cargo.toml")
        .trim_matches('/')
}

fn path_segments_match(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }
    let (pattern_segment, remaining_pattern) = pattern.split_once('/').unwrap_or((pattern, ""));
    if pattern_segment == "**" {
        if remaining_pattern.is_empty() {
            return true;
        }
        if path_segments_match(remaining_pattern, path) {
            return true;
        }
        return path
            .split_once('/')
            .is_some_and(|(_, remaining_path)| path_segments_match(pattern, remaining_path));
    }
    let (path_segment, remaining_path) = path.split_once('/').unwrap_or((path, ""));
    segment_matches(pattern_segment, path_segment)
        && path_segments_match(remaining_pattern, remaining_path)
}

fn segment_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star = None;
    let mut retry_value = 0usize;
    while value_index < value.len() {
        if pattern
            .get(pattern_index)
            .is_some_and(|byte| *byte == b'?' || *byte == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry_value = value_index;
        } else if let Some(star_index) = star {
            retry_value += 1;
            value_index = retry_value;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn append_missing_resolver(workspace: &Workspace<'_>, findings: &mut Vec<Finding>) {
    let Some(table) = workspace
        .root
        .value
        .get("workspace")
        .and_then(Value::as_table)
    else {
        return;
    };
    if workspace.root.value.get("package").is_some() || table.contains_key("resolver") {
        return;
    }
    let edition = workspace_edition(workspace);
    if edition < 2021 {
        return;
    }
    let resolver = if edition >= 2024 { 3 } else { 2 };
    findings.push(finding(
        "rust-workspace-missing-resolver",
        workspace.root.path,
        section_line(workspace.root.source, "workspace"),
        format!(
            "virtual workspace with edition {edition} members does not declare resolver = \"{resolver}\""
        ),
    ));
}

fn workspace_edition(workspace: &Workspace<'_>) -> u32 {
    let inherited = workspace
        .root
        .value
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("edition"))
        .and_then(Value::as_str)
        .and_then(|edition| edition.parse::<u32>().ok())
        .unwrap_or_default();
    workspace
        .members
        .iter()
        .filter_map(|manifest| {
            manifest
                .value
                .get("package")
                .and_then(|package| package.get("edition"))
                .and_then(Value::as_str)
                .and_then(|edition| edition.parse::<u32>().ok())
        })
        .fold(inherited, u32::max)
}

fn append_ignored_member_sections(workspace: &Workspace<'_>, findings: &mut Vec<Finding>) {
    for member in workspace
        .members
        .iter()
        .copied()
        .filter(|member| member.path != workspace.root.path)
    {
        let sections = ["patch", "profile", "replace"]
            .into_iter()
            .filter(|section| member.value.get(*section).is_some())
            .collect::<Vec<_>>();
        if sections.is_empty() {
            continue;
        }
        let line = sections
            .iter()
            .map(|section| section_prefix_line(member.source, section))
            .min()
            .unwrap_or(1);
        let mut result = finding(
            "rust-ignored-workspace-member-section",
            member.path,
            line,
            format!(
                "Cargo ignores [{}] configuration in workspace member manifests",
                sections.join(", ")
            ),
        );
        result.related_files.push(workspace.root.path.to_owned());
        findings.push(result);
    }
}

fn section_prefix_line(source: &str, section: &str) -> usize {
    source
        .lines()
        .position(|line| {
            let line = line.trim();
            line.strip_prefix('[').is_some_and(|body| {
                body.starts_with(section)
                    && body
                        .as_bytes()
                        .get(section.len())
                        .is_some_and(|next| matches!(next, b'.' | b']'))
            })
        })
        .map_or(1, |index| index + 1)
}

// code-buster-ignore complex-function: one CI scan must retain broad coverage and the first unscoped command.
fn append_partial_workspace_ci(
    context: &SourceAnalysisContext<'_>,
    workspace: &Workspace<'_>,
    findings: &mut Vec<Finding>,
) {
    if workspace.root.path != "Cargo.toml"
        || workspace.root.value.get("package").is_none()
        || workspace.members.len() < 2
        || defaults_cover_all_members(workspace)
    {
        return;
    }
    let mut first_unscoped = None;
    let mut broad_command = false;
    for (path, source) in context
        .auxiliary_files()
        .iter()
        .filter(|(path, _)| is_ci_path(path))
    {
        let direct = is_sourcehut_path(path);
        if !direct && DELEGATED_WORKSPACE_CI.is_match(source) {
            broad_command = true;
        }
        if !direct && source.contains("working-directory:") {
            continue;
        }
        for_each_ci_command_line(path, source, |line_index, raw_line, changed_directory| {
            let line = if direct {
                raw_line
            } else {
                ci_line_without_comment(raw_line)
            };
            if direct
                && DELEGATED_WORKSPACE_CI
                    .find(line)
                    .is_some_and(|command| command.start() == 0)
            {
                broad_command = true;
            }
            for command in WORKSPACE_CARGO_COMMAND.find_iter(line) {
                if direct && command.start() != 0 {
                    continue;
                }
                let text = command.as_str();
                if has_workspace_scope(text) {
                    broad_command = true;
                } else if !has_package_scope(text)
                    && !changed_directory
                    && !line[..command.start()].contains("cd ")
                    && first_unscoped.is_none()
                {
                    first_unscoped = Some((path.as_str(), line_index + 1));
                }
            }
        });
    }
    if broad_command {
        return;
    }
    if let Some((path, line)) = first_unscoped {
        let mut result = finding(
            "rust-partial-workspace-ci",
            path,
            line,
            "Cargo CI command selects only the root package of a multi-package workspace"
                .to_owned(),
        );
        result.related_files.extend(
            workspace
                .members
                .iter()
                .filter(|member| member.path != workspace.root.path)
                .map(|member| member.path.to_owned()),
        );
        findings.push(result);
    }
}

fn defaults_cover_all_members(workspace: &Workspace<'_>) -> bool {
    let Some(defaults) = workspace
        .root
        .value
        .get("workspace")
        .and_then(|workspace| workspace.get("default-members"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    workspace.members.iter().all(|member| {
        member.path == workspace.root.path
            || relative_manifest_directory(workspace.root.path, member.path)
                .is_some_and(|relative| matches_any_member(defaults, relative))
    })
}

fn has_workspace_scope(command: &str) -> bool {
    command
        .split_ascii_whitespace()
        .any(|token| matches!(token, "--workspace" | "--all"))
}

fn has_package_scope(command: &str) -> bool {
    command.split_ascii_whitespace().any(|token| {
        matches!(token, "--manifest-path" | "--package" | "-p")
            || token.starts_with("--manifest-path=")
            || token.starts_with("--package=")
    })
}

fn append_dependency_policy(workspace: &Workspace<'_>, findings: &mut Vec<Finding>) {
    let mut dependencies = BTreeMap::<String, Vec<DependencyDeclaration<'_>>>::new();
    for member in workspace
        .members
        .iter()
        .filter(|member| package_is_internal(member, workspace.root))
    {
        let Some(table) = member.value.get("dependencies").and_then(Value::as_table) else {
            continue;
        };
        for (name, specification) in table {
            let Some(version) = direct_registry_version(name, specification) else {
                continue;
            };
            dependencies
                .entry(name.clone())
                .or_default()
                .push(DependencyDeclaration {
                    manifest: member,
                    version,
                });
        }
    }
    for (name, declarations) in dependencies {
        let versions = declarations
            .iter()
            .map(|declaration| declaration.version)
            .collect::<BTreeSet<_>>();
        if versions.len() > 1 && !equivalent_requirements(&versions) {
            let rendered = versions.iter().copied().collect::<Vec<_>>().join(", ");
            let mut result = dependency_finding(
                "rust-workspace-dependency-version-drift",
                &name,
                &declarations,
                format!(
                    "workspace dependency {name} uses inconsistent version requirements: {rendered}"
                ),
            );
            add_related_manifests(&mut result, &declarations);
            findings.push(result);
        } else if declarations.len() >= 3 {
            let version = versions.first().copied().unwrap_or_default();
            let mut result = dependency_finding(
                "rust-repeated-workspace-dependency",
                &name,
                &declarations,
                format!(
                    "dependency {name} {version} is repeated in {} workspace members",
                    declarations.len()
                ),
            );
            add_related_manifests(&mut result, &declarations);
            findings.push(result);
        }
    }
}

fn equivalent_requirements(versions: &BTreeSet<&str>) -> bool {
    let Some(first) = versions
        .first()
        .and_then(|version| normalized_requirement(version))
    else {
        return false;
    };
    versions.iter().skip(1).all(|version| {
        normalized_requirement(version).is_some_and(|requirement| requirement == first)
    })
}

fn normalized_requirement(version: &str) -> Option<VersionReq> {
    let mut requirement = VersionReq::parse(version).ok()?;
    for comparator in &mut requirement.comparators {
        if comparator.op != Op::Caret {
            continue;
        }
        if comparator.major != 0 {
            comparator.minor.get_or_insert(0);
        }
        if comparator.major != 0 || comparator.minor.is_some_and(|minor| minor != 0) {
            comparator.patch.get_or_insert(0);
        }
    }
    Some(requirement)
}

fn package_is_internal(manifest: &CargoManifest<'_>, root: &CargoManifest<'_>) -> bool {
    let Some(package) = manifest.value.get("package").and_then(Value::as_table) else {
        return false;
    };
    let publish = super::package_field(manifest, Some(root), "publish");
    if publish.and_then(Value::as_bool) == Some(false)
        || publish.and_then(Value::as_array).is_some_and(Vec::is_empty)
        || super::package_field(manifest, Some(root), "version").and_then(Value::as_str)
            == Some("0.0.0")
        || super::package_field(manifest, Some(root), "description")
            .and_then(Value::as_str)
            .is_some_and(|description| INTERNAL_CRATE_DESCRIPTION.is_match(description))
    {
        return true;
    }
    ![
        "categories",
        "description",
        "documentation",
        "homepage",
        "keywords",
        "license",
        "readme",
        "repository",
    ]
    .iter()
    .any(|field| package.contains_key(*field))
}

struct DependencyDeclaration<'a> {
    manifest: &'a CargoManifest<'a>,
    version: &'a str,
}

fn direct_registry_version<'a>(name: &str, specification: &'a Value) -> Option<&'a str> {
    if let Some(version) = specification.as_str() {
        return Some(version);
    }
    let table = specification.as_table()?;
    if table.get("workspace").and_then(Value::as_bool) == Some(true)
        || table.contains_key("path")
        || table.contains_key("git")
        || table
            .get("package")
            .and_then(Value::as_str)
            .is_some_and(|package| package != name)
    {
        return None;
    }
    table.get("version").and_then(Value::as_str)
}

fn dependency_finding(
    code: &str,
    name: &str,
    declarations: &[DependencyDeclaration<'_>],
    message: String,
) -> Finding {
    let primary = declarations[0].manifest;
    finding(
        code,
        primary.path,
        dependency_line(primary.source, name),
        message,
    )
}

fn add_related_manifests(finding: &mut Finding, declarations: &[DependencyDeclaration<'_>]) {
    finding.related_files.extend(
        declarations
            .iter()
            .skip(1)
            .map(|declaration| declaration.manifest.path.to_owned()),
    );
}

fn dependency_line(source: &str, name: &str) -> usize {
    let mut in_dependencies = false;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[dependencies]";
            continue;
        }
        if in_dependencies
            && trimmed
                .split_once('=')
                .is_some_and(|(candidate, _)| candidate.trim().trim_matches(['\'', '"']) == name)
        {
            return index + 1;
        }
    }
    section_line(source, "dependencies")
}

fn append_redundant_member_lockfiles(
    context: &SourceAnalysisContext<'_>,
    workspace: &Workspace<'_>,
    findings: &mut Vec<Finding>,
) {
    let root_lock = joined_path(manifest_directory(workspace.root.path), "Cargo.lock");
    if !context.auxiliary_files().contains_key(&root_lock) {
        return;
    }
    for member in workspace
        .members
        .iter()
        .copied()
        .filter(|member| member.path != workspace.root.path)
    {
        let member_lock = joined_path(manifest_directory(member.path), "Cargo.lock");
        if !context.auxiliary_files().contains_key(&member_lock) {
            continue;
        }
        let mut result = finding(
            "rust-redundant-member-lockfile",
            &member_lock,
            1,
            "workspace member lockfile is ignored in favor of the workspace lockfile".to_owned(),
        );
        result.related_files.push(root_lock.clone());
        findings.push(result);
    }
}

fn joined_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

static INTERNAL_CRATE_DESCRIPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\binternal (?:component )?crate\b").unwrap());
static DELEGATED_WORKSPACE_CI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)\bcargo\s+(?:\+\S+\s+)?run\b[^\r\n;&|]*(?:-p\s+|--package(?:=|\s+))(?:ci|xtask)\b[^\r\n;&|]*--\s*(?:check|compile|lint|test)\b",
    )
    .unwrap()
});

static WORKSPACE_CARGO_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)cargo\s+(?:\+\S+\s+)?(?:check|test|clippy|nextest\s+run|hack\s+(?:check|test|clippy))\b[^;&|]*"#,
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn reports_workspace_policy_gaps_once_with_related_members() {
        let findings = analyze_project([
            (
                "Cargo.toml",
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\n\n[workspace]\nmembers = [\"crates/*\"]\n\n[dependencies]\nserde = \"1\"",
            ),
            ("Cargo.lock", "version = 4"),
            (
                "crates/api/Cargo.toml",
                "[package]\nname = \"api\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\n\n[dependencies]\nserde = \"1.0\"\n\n[profile.release]\nlto = true",
            ),
            ("crates/api/Cargo.lock", "version = 4"),
            (
                "crates/cli/Cargo.toml",
                "[package]\nname = \"cli\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\n\n[dependencies]\nserde = \"1\"",
            ),
            (
                ".github/workflows/ci.yml",
                "steps:\n  - run: cargo test --locked\n  - run: cargo clippy --locked\n  - run: cargo fmt -- --check\n  - run: cargo audit",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec![
                "rust-ignored-workspace-member-section",
                "rust-partial-workspace-ci",
                "rust-repeated-workspace-dependency",
                "rust-redundant-member-lockfile",
            ]
        );
        assert_eq!(findings[1].related_files.len(), 2);
        assert_eq!(findings[2].related_files.len(), 2);
    }

    #[test]
    fn reports_virtual_workspace_resolver_and_repeated_dependency() {
        let findings = analyze_project([
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"a\", \"b\", \"c\"]\n\n[workspace.package]\nedition = \"2024\"",
            ),
            (
                "a/Cargo.toml",
                "[package]\nname = \"a\"\nedition.workspace = true\nrust-version = \"1.85\"\n[dependencies]\nserde = \"1\"",
            ),
            (
                "b/Cargo.toml",
                "[package]\nname = \"b\"\nedition.workspace = true\nrust-version = \"1.85\"\n[dependencies]\nserde = \"1\"",
            ),
            (
                "c/Cargo.toml",
                "[package]\nname = \"c\"\nedition.workspace = true\nrust-version = \"1.85\"\n[dependencies]\nserde = \"1\"",
            ),
        ]);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>(),
            vec![
                "rust-workspace-missing-resolver",
                "rust-repeated-workspace-dependency",
            ]
        );
        assert_eq!(findings[1].related_files, ["b/Cargo.toml", "c/Cargo.toml"]);
    }

    #[test]
    fn compares_cargo_requirements_without_conflating_different_version_floors() {
        for (left, right, drift) in [
            ("1", "1.0", false),
            ("^1.0", "1.0.0", false),
            ("0.2", "^0.2.0", false),
            ("0", "^0", false),
            ("0", "0.0", true),
            ("0.0", "0.0.0", true),
            ("1.2", "1.2.3", true),
            ("2", "2.0.12", true),
            ("~1", "~1.0", true),
            ("=1", "=1.0", true),
            ("1", "2", true),
        ] {
            let member = |name, version| {
                format!(
                    "[package]\nname = \"{name}\"\npublish = false\n\
                     [dependencies]\nserde = \"{version}\""
                )
            };
            let a = member("a", left);
            let b = member("b", right);
            let findings = analyze_project([
                (
                    "Cargo.toml",
                    "[workspace]\nresolver = \"3\"\nmembers = [\"a\", \"b\"]",
                ),
                ("a/Cargo.toml", a.as_str()),
                ("b/Cargo.toml", b.as_str()),
            ]);
            assert_eq!(findings.len(), usize::from(drift), "{left} / {right}");
            if drift {
                assert_eq!(findings[0].code, "rust-workspace-dependency-version-drift");
                assert_eq!(findings[0].path, "a/Cargo.toml");
                assert_eq!(findings[0].line, 5);
                assert_eq!(findings[0].confidence, "high");
                assert_eq!(findings[0].related_files, ["b/Cargo.toml"]);
            }
        }
    }

    #[test]
    fn accepts_explicit_workspace_policy_and_independent_nested_projects() {
        let findings = analyze_project([
            (
                "Cargo.toml",
                "[package]\nname = \"root\"\nedition = \"2024\"\nrust-version = \"1.85\"\n[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\ndefault-members = [\".\", \"crates/*\"]\n[workspace.dependencies]\nserde = \"1\"",
            ),
            ("Cargo.lock", "version = 4"),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\nedition = \"2024\"\nrust-version = \"1.85\"\n[dependencies]\nserde.workspace = true",
            ),
            (
                "tools/Cargo.toml",
                "[package]\nname = \"tools\"\nedition = \"2024\"\nrust-version = \"1.85\"\n[workspace]\nmembers = [\".\"]\n[profile.release]\nlto = true",
            ),
            (
                ".github/workflows/ci.yml",
                "steps:\n  - run: cargo test --workspace --locked\n  - run: cargo clippy --workspace --locked\n  - run: cargo fmt -- --check\n  - run: cargo audit",
            ),
        ]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn applies_inherited_publication_policy_to_workspace_dependency_advice() {
        for (root_policy, member_policy, should_report) in [
            ("false", "publish.workspace=true", true),
            ("true", "publish.workspace=true", false),
            ("false", "publish=true", false),
            ("true", "publish=false", true),
        ] {
            let root = format!(
                "[workspace]\nresolver='3'\nmembers=['a','b','c']\n\
                 [workspace.package]\npublish={root_policy}\n"
            );
            let member = |name, version| {
                format!(
                    "[package]\nname='{name}'\nversion='1.0.0'\n{member_policy}\n\
                 description='Reusable library'\nlicense='MIT'\n\
                 [dependencies]\nserde='{version}'\nlog='0.4'\n"
                )
            };
            let a = member("a", "1");
            let b = member("b", "2");
            let c = member("c", "1");
            let findings = analyze_project([
                ("Cargo.toml", root.as_str()),
                ("a/Cargo.toml", a.as_str()),
                ("b/Cargo.toml", b.as_str()),
                ("c/Cargo.toml", c.as_str()),
            ]);
            let policy_findings = findings
                .iter()
                .filter(|finding| {
                    matches!(
                        finding.code.as_str(),
                        "rust-workspace-dependency-version-drift"
                            | "rust-repeated-workspace-dependency"
                    )
                })
                .collect::<Vec<_>>();
            if should_report {
                assert_eq!(policy_findings.len(), 2, "{root_policy}/{member_policy}");
                assert!(policy_findings.iter().all(|finding| {
                    finding.path == "a/Cargo.toml"
                        && finding
                            .related_files
                            .iter()
                            .map(String::as_str)
                            .eq(["b/Cargo.toml", "c/Cargo.toml"])
                }));
            } else {
                assert!(policy_findings.is_empty(), "{root_policy}/{member_policy}");
            }
        }
    }

    #[test]
    fn ignores_dependency_policy_for_published_workspace_members() {
        let findings = analyze_project([
            (
                "Cargo.toml",
                "[workspace]\nresolver = \"3\"\nmembers = [\"a\", \"b\", \"c\"]\n\n[workspace.package]\nedition = \"2024\"",
            ),
            (
                "a/Cargo.toml",
                "[package]\nname = \"a\"\nversion = \"1.0.0\"\ndescription = \"Published library A\"\nlicense = \"MIT\"\n[dependencies]\nserde = \"1\"",
            ),
            (
                "b/Cargo.toml",
                "[package]\nname = \"b\"\nversion = \"1.0.0\"\ndescription = \"Published library B\"\nlicense = \"MIT\"\n[dependencies]\nserde = \"1.0\"",
            ),
            (
                "c/Cargo.toml",
                "[package]\nname = \"c\"\nversion = \"1.0.0\"\ndescription = \"Published library C\"\nlicense = \"MIT\"\n[dependencies]\nserde = \"1.0.100\"",
            ),
        ]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn accepts_a_delegated_workspace_ci_runner() {
        let findings = analyze_project([
            (
                "Cargo.toml",
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\nmembers = [\"app\", \"tools/ci\"]",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"",
            ),
            (
                "tools/ci/Cargo.toml",
                "[package]\nname = \"ci\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false",
            ),
            (
                ".github/workflows/ci.yml",
                "steps:\n  - run: cargo run -p ci -- test",
            ),
        ]);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn sourcehut_workspace_coverage_requires_executable_tasks() {
        for coverage in [
            "echo 'cargo test --workspace'",
            "# cargo run -p ci -- test",
            "cd member && cargo test --locked",
        ] {
            let workflow = format!(
                "environment:\n  RUNNER: cargo run -p ci -- test\n  DIRECTORY: 'working-directory:'\ndescription: |\n  cargo test --workspace\ntasks:\n  - test: |\n      cargo test --locked\n  - coverage: |\n      {coverage}"
            );
            let findings = analyze_project([
                (
                    "Cargo.toml",
                    "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\nresolver = \"3\"\nmembers = [\"member\"]",
                ),
                (
                    "member/Cargo.toml",
                    "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"",
                ),
                (".builds/ci.yml", workflow.as_str()),
            ]);

            assert_eq!(
                findings.len(),
                1,
                "unexpected findings for {coverage}: {findings:?}"
            );
            assert_eq!(findings[0].code, "rust-partial-workspace-ci");
            assert_eq!(findings[0].path, ".builds/ci.yml");
            assert_eq!(findings[0].line, 8);
            assert_eq!(findings[0].confidence, "high");
            assert_eq!(findings[0].related_files, ["member/Cargo.toml"]);
        }
    }

    #[test]
    fn accepts_sourcehut_workspace_commands_and_delegated_ci_runners() {
        for coverage in ["cargo test --workspace --locked", "cargo run -p ci -- test"] {
            let workflow = format!(
                "tasks:\n  - test: |\n      cargo test --locked\n  - coverage: |\n      {coverage}"
            );
            let findings = analyze_project([
                (
                    "Cargo.toml",
                    "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\nresolver = \"3\"\nmembers = [\"member\"]",
                ),
                (
                    "member/Cargo.toml",
                    "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"",
                ),
                (".build.yml", workflow.as_str()),
            ]);

            assert!(
                findings.is_empty(),
                "unexpected findings for {coverage}: {findings:?}"
            );
        }
    }

    #[test]
    fn member_patterns_do_not_cross_path_segments() {
        assert!(member_pattern_matches("crates/*", "crates/api"));
        assert!(!member_pattern_matches("crates/*", "crates/api/nested"));
        assert!(member_pattern_matches("crates/**", "crates/api/nested"));
        assert!(member_pattern_matches("crates/a?i", "crates/api"));
    }

    fn analyze_project<const N: usize>(files: [(&str, &str); N]) -> Vec<Finding> {
        let auxiliary = files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let sources = BTreeMap::new();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        let manifests = super::super::parse_manifests(&context);
        analyze(&context, &manifests)
    }
}
