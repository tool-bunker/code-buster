use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::findings::Finding;

use super::{finding, line_containing};

const DEPENDENCY_DRIFT: &str = "npm-workspace-dependency-version-drift";

pub(super) fn analyze(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let manifests = parse_manifests(auxiliary);
    manifests
        .iter()
        .filter(|manifest| manifest.workspaces.is_some())
        .flat_map(|root| workspace_findings(root, &manifests))
        .collect()
}

fn workspace_findings<'a>(root: &'a Manifest<'a>, manifests: &'a [Manifest<'a>]) -> Vec<Finding> {
    let mut dependencies = BTreeMap::<&str, Vec<Declaration<'_>>>::new();
    for member in workspace_members(root, manifests)
        .into_iter()
        .filter(|member| member.private)
    {
        collect_member_dependencies(member, &mut dependencies);
    }
    dependency_findings(dependencies)
}

fn collect_member_dependencies<'a>(
    member: &'a Manifest<'a>,
    dependencies: &mut BTreeMap<&'a str, Vec<Declaration<'a>>>,
) {
    let table = member.value.get("dependencies").and_then(Value::as_object);
    if let Some(table) = table {
        for (name, requirement) in table {
            let Some(requirement) = requirement.as_str() else {
                continue;
            };
            let Some(major) = direct_major(requirement) else {
                continue;
            };
            dependencies.entry(name).or_default().push(Declaration {
                manifest: member,
                requirement,
                major,
            });
        }
    }
    if table.is_none_or(|dependencies| !dependencies.contains_key("typescript"))
        && let Some(requirement) = member
            .value
            .get("devDependencies")
            .and_then(Value::as_object)
            .and_then(|dependencies| dependencies.get("typescript"))
            .and_then(Value::as_str)
        && let Some(major) = direct_major(requirement)
    {
        dependencies
            .entry("typescript")
            .or_default()
            .push(Declaration {
                manifest: member,
                requirement,
                major,
            });
    }
}

fn dependency_findings(dependencies: BTreeMap<&str, Vec<Declaration<'_>>>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, declarations) in dependencies {
        let majors = declarations
            .iter()
            .map(|declaration| declaration.major)
            .collect::<BTreeSet<_>>();
        if majors.len() < 2 {
            continue;
        }
        let primary = declarations[0];
        let requirements = declarations
            .iter()
            .map(|declaration| declaration.requirement)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(finding(
            DEPENDENCY_DRIFT,
            primary.manifest.path,
            line_containing(primary.manifest.source, &format!("\"{name}\"")),
            format!(
                "npm workspace dependency {name} uses incompatible major requirements: {requirements}"
            ),
            declarations
                .iter()
                .skip(1)
                .map(|declaration| declaration.manifest.path.to_owned())
                .collect(),
        ));
    }
    findings
}

struct Manifest<'a> {
    path: &'a str,
    source: &'a str,
    value: Value,
    private: bool,
    workspaces: Option<Vec<String>>,
}

#[derive(Clone, Copy)]
struct Declaration<'a> {
    manifest: &'a Manifest<'a>,
    requirement: &'a str,
    major: u64,
}

fn parse_manifests(auxiliary: &BTreeMap<String, String>) -> Vec<Manifest<'_>> {
    auxiliary
        .iter()
        .filter(|(path, _)| {
            Path::new(path).file_name().and_then(|name| name.to_str()) == Some("package.json")
        })
        .filter_map(|(path, source)| {
            let value = serde_json::from_str::<Value>(source).ok()?;
            let private = value.get("private").and_then(Value::as_bool) == Some(true);
            let workspaces = workspace_literals(&value);
            Some(Manifest {
                path,
                source,
                value,
                private,
                workspaces,
            })
        })
        .collect()
}

fn workspace_literals(value: &Value) -> Option<Vec<String>> {
    let workspaces = value.get("workspaces")?;
    let values = workspaces
        .as_array()
        .or_else(|| workspaces.get("packages").and_then(Value::as_array))?;
    let members = values
        .iter()
        .filter_map(Value::as_str)
        .filter(|member| !member.contains(['*', '?', '[', ']']))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (!members.is_empty()).then_some(members)
}

fn workspace_members<'a>(
    root: &Manifest<'a>,
    manifests: &'a [Manifest<'a>],
) -> Vec<&'a Manifest<'a>> {
    let base = Path::new(root.path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let expected = root
        .workspaces
        .as_ref()
        .into_iter()
        .flatten()
        .filter_map(|member| normalize(base.join(member).join("package.json")))
        .collect::<BTreeSet<_>>();
    manifests
        .iter()
        .filter(|manifest| expected.contains(manifest.path))
        .collect()
}

fn normalize(path: PathBuf) -> Option<String> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => result.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(result.to_string_lossy().replace('\\', "/"))
}

fn direct_major(requirement: &str) -> Option<u64> {
    let requirement = requirement.trim();
    const NON_REGISTRY_PREFIXES: &[&str] = &[
        "workspace:",
        "file:",
        "link:",
        "git:",
        "http:",
        "https:",
        "npm:",
    ];
    if requirement.is_empty()
        || requirement.contains([' ', ',', '|', '<', '>', '*', 'x', 'X'])
        || NON_REGISTRY_PREFIXES
            .iter()
            .any(|prefix| requirement.starts_with(prefix))
    {
        return None;
    }
    let numeric = requirement.trim_start_matches(['^', '~', '=', 'v']);
    let major = numeric.split('.').next()?.parse::<u64>().ok()?;
    (major > 0).then_some(major)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_incompatible_private_workspace_dependency_majors() {
        let files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"private":true,"workspaces":["packages/a","packages/b","packages/public"]}"#
                    .to_owned(),
            ),
            (
                "packages/a/package.json".to_owned(),
                r#"{"private":true,"dependencies":{"react":"^18.2.0"}}"#.to_owned(),
            ),
            (
                "packages/b/package.json".to_owned(),
                r#"{"private":true,"dependencies":{"react":"^19.0.0"}}"#.to_owned(),
            ),
            (
                "packages/public/package.json".to_owned(),
                r#"{"dependencies":{"react":"^17.0.0"}}"#.to_owned(),
            ),
        ]);
        let findings = analyze(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, DEPENDENCY_DRIFT);
        assert_eq!(findings[0].related_files, ["packages/b/package.json"]);
    }

    #[test]
    fn accepts_compatible_or_unresolved_workspace_requirements() {
        let files = BTreeMap::from([
            ("package.json".to_owned(), r#"{"private":true,"workspaces":{"packages":["packages/a","packages/b","packages/*"]}}"#.to_owned()),
            ("packages/a/package.json".to_owned(), r#"{"private":true,"dependencies":{"react":"^18.2.0","local":"workspace:*"}}"#.to_owned()),
            ("packages/b/package.json".to_owned(), r#"{"private":true,"dependencies":{"react":"~18.3.0","local":"file:../local"}}"#.to_owned()),
        ]);
        assert!(analyze(&files).is_empty());
    }

    #[test]
    fn reports_incompatible_typescript_compiler_majors_in_private_members() {
        let files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"private":true,"workspaces":["packages/a","packages/b"]}"#.to_owned(),
            ),
            (
                "packages/a/package.json".to_owned(),
                r#"{"private":true,"devDependencies":{"typescript":"^5.8.0"}}"#.to_owned(),
            ),
            (
                "packages/b/package.json".to_owned(),
                r#"{"private":true,"devDependencies":{"typescript":"^6.0.0"}}"#.to_owned(),
            ),
        ]);
        let findings = analyze(&files);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("typescript"));
    }
}
