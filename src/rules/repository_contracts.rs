use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::dependency_graph::DependencyGraph;
use crate::discovery::{PreparedPreview, is_builtin_production_path};
use crate::findings::{Finding, Severity};
use crate::source_analysis_context::SourceAnalysisContext;

pub fn analyze(
    prepared: &PreparedPreview,
    context: &SourceAnalysisContext<'_>,
    graph: &DependencyGraph,
) -> Vec<Finding> {
    let mut findings = production_imports_test_code(prepared, graph);
    findings.extend(missing_manifest_paths(context.auxiliary_files()));
    findings
}

fn production_imports_test_code(
    prepared: &PreparedPreview,
    graph: &DependencyGraph,
) -> Vec<Finding> {
    if prepared.config.include_all
        || prepared.config.include_tests
        || prepared.config.include_examples
    {
        return Vec::new();
    }
    let excluded = prepared
        .excluded_source_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    for source in graph.nodes() {
        for target in graph
            .classified_dependencies(source)
            .filter(|target| excluded.contains(target))
        {
            let line = dependency_line(prepared.sources.get(source), target);
            findings.push(Finding {
                code: "production-imports-test-code".to_owned(),
                severity: Severity::Error,
                path: source.to_owned(),
                line,
                end_line: line,
                message: format!("production source imports test-only file `{target}`"),
                confidence: "high".to_owned(),
                why: "Production code must not depend on test, fixture, mock, benchmark, or example code."
                    .to_owned(),
                suggestion: "Move the shared implementation into production code and import it from both locations."
                    .to_owned(),
                related_files: vec![target.to_owned()],
                snippet: String::new(),
                code_flow: Vec::new(),
            });
        }
    }
    findings
}

fn dependency_line(source: Option<&String>, target: &str) -> usize {
    let stem = Path::new(target)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(target);
    source
        .into_iter()
        .flat_map(|source| source.lines())
        .position(|line| line.contains(stem))
        .map_or(1, |index| index + 1)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestReference {
    manifest: String,
    line: usize,
    kind: &'static str,
    target: String,
    candidates: Vec<PathBuf>,
}

impl ManifestReference {
    fn marker(&self) -> String {
        format!(
            "@manifest-exists/{}:{}:{}:{}",
            self.manifest, self.line, self.kind, self.target
        )
    }
}

pub(crate) fn manifest_existence_markers(
    root: &Path,
    auxiliary: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    manifest_references(auxiliary)
        .into_iter()
        .map(|reference| {
            let exists = reference
                .candidates
                .iter()
                .any(|candidate| root.join(candidate).is_file());
            (reference.marker(), exists.to_string())
        })
        .collect()
}

fn missing_manifest_paths(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    manifest_references(auxiliary)
        .into_iter()
        .filter(|reference| {
            auxiliary
                .get(&reference.marker())
                .is_some_and(|exists| exists == "false")
        })
        .map(|reference| Finding {
            code: "manifest-local-path-missing".to_owned(),
            severity: Severity::Error,
            path: reference.manifest,
            line: reference.line,
            end_line: reference.line,
            message: format!(
                "{} points to missing local path `{}`",
                reference.kind, reference.target
            ),
            confidence: "high".to_owned(),
            why: "A literal local manifest reference cannot be resolved from the checked-out repository."
                .to_owned(),
            suggestion: "Add the referenced file or package, or correct the manifest path."
                .to_owned(),
            related_files: vec![reference.target],
            snippet: String::new(),
            code_flow: Vec::new(),
        })
        .collect()
}

fn manifest_references(auxiliary: &BTreeMap<String, String>) -> Vec<ManifestReference> {
    let mut references = Vec::new();
    for (manifest, source) in auxiliary {
        if !is_builtin_production_path(manifest) {
            continue;
        }
        match Path::new(manifest)
            .file_name()
            .and_then(|name| name.to_str())
        {
            Some("Cargo.toml") => cargo_references(manifest, source, &mut references),
            Some("package.json") => package_references(manifest, source, &mut references),
            Some("pyproject.toml") => python_references(manifest, source, &mut references),
            _ => {}
        }
    }
    references
}

fn cargo_references(manifest: &str, source: &str, references: &mut Vec<ManifestReference>) {
    let Ok(value) = toml::from_str::<TomlValue>(source) else {
        return;
    };
    let base = manifest_parent(manifest);
    cargo_workspace_references(manifest, source, &base, &value, references);
    if let Some(root) = value.as_table() {
        cargo_dependency_section_references(manifest, source, &base, root, references);
    }
    cargo_target_dependency_references(manifest, source, &base, &value, references);
    cargo_declared_target_references(manifest, source, &base, &value, references);
}

fn cargo_workspace_references(
    manifest: &str,
    source: &str,
    base: &Path,
    value: &TomlValue,
    references: &mut Vec<ManifestReference>,
) {
    let Some(workspace) = value.get("workspace").and_then(TomlValue::as_table) else {
        return;
    };
    if let Some(members) = workspace.get("members").and_then(TomlValue::as_array) {
        for member in members
            .iter()
            .filter_map(TomlValue::as_str)
            .filter(|member| !contains_glob(member))
        {
            push_reference(
                references,
                manifest,
                source,
                "Cargo workspace member",
                member,
                vec![base.join(member).join("Cargo.toml")],
            );
        }
    }
    if let Some(dependencies) = workspace.get("dependencies").and_then(TomlValue::as_table) {
        cargo_dependency_references(manifest, source, base, dependencies, references);
    }
}

fn cargo_dependency_section_references(
    manifest: &str,
    source: &str,
    base: &Path,
    sections: &toml::map::Map<String, TomlValue>,
    references: &mut Vec<ManifestReference>,
) {
    for name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = sections.get(name).and_then(TomlValue::as_table) {
            cargo_dependency_references(manifest, source, base, dependencies, references);
        }
    }
}

fn cargo_target_dependency_references(
    manifest: &str,
    source: &str,
    base: &Path,
    value: &TomlValue,
    references: &mut Vec<ManifestReference>,
) {
    let Some(targets) = value.get("target").and_then(TomlValue::as_table) else {
        return;
    };
    for target in targets.values().filter_map(TomlValue::as_table) {
        cargo_dependency_section_references(manifest, source, base, target, references);
    }
}

fn cargo_declared_target_references(
    manifest: &str,
    source: &str,
    base: &Path,
    value: &TomlValue,
    references: &mut Vec<ManifestReference>,
) {
    cargo_target_reference(
        manifest,
        source,
        base,
        "Cargo library target",
        value.get("lib"),
        references,
    );
    for (key, kind) in [
        ("bin", "Cargo binary target"),
        ("example", "Cargo example target"),
        ("test", "Cargo test target"),
        ("bench", "Cargo benchmark target"),
    ] {
        if let Some(targets) = value.get(key).and_then(TomlValue::as_array) {
            for target in targets {
                cargo_target_reference(manifest, source, base, kind, Some(target), references);
            }
        }
    }
}

fn cargo_dependency_references(
    manifest: &str,
    source: &str,
    base: &Path,
    dependencies: &toml::map::Map<String, TomlValue>,
    references: &mut Vec<ManifestReference>,
) {
    for dependency in dependencies.values().filter_map(TomlValue::as_table) {
        let Some(path) = dependency.get("path").and_then(TomlValue::as_str) else {
            continue;
        };
        push_reference(
            references,
            manifest,
            source,
            "Cargo path dependency",
            path,
            vec![base.join(path).join("Cargo.toml")],
        );
    }
}

fn cargo_target_reference(
    manifest: &str,
    source: &str,
    base: &Path,
    kind: &'static str,
    target: Option<&TomlValue>,
    references: &mut Vec<ManifestReference>,
) {
    let Some(path) = target
        .and_then(TomlValue::as_table)
        .and_then(|target| target.get("path"))
        .and_then(TomlValue::as_str)
    else {
        return;
    };
    push_reference(
        references,
        manifest,
        source,
        kind,
        path,
        vec![base.join(path)],
    );
}

fn package_references(manifest: &str, source: &str, references: &mut Vec<ManifestReference>) {
    let Ok(value) = serde_json::from_str::<JsonValue>(source) else {
        return;
    };
    let base = manifest_parent(manifest);
    match value.get("bin") {
        Some(JsonValue::String(path)) => push_reference(
            references,
            manifest,
            source,
            "package executable",
            path,
            vec![base.join(path)],
        ),
        Some(JsonValue::Object(bins)) => {
            for path in bins.values().filter_map(JsonValue::as_str) {
                push_reference(
                    references,
                    manifest,
                    source,
                    "package executable",
                    path,
                    vec![base.join(path)],
                );
            }
        }
        _ => {}
    }
    let workspaces = value.get("workspaces").and_then(|workspaces| {
        workspaces
            .as_array()
            .or_else(|| workspaces.get("packages").and_then(JsonValue::as_array))
    });
    if let Some(workspaces) = workspaces {
        for workspace in workspaces.iter().filter_map(JsonValue::as_str) {
            if !contains_glob(workspace) {
                push_reference(
                    references,
                    manifest,
                    source,
                    "package workspace member",
                    workspace,
                    vec![base.join(workspace).join("package.json")],
                );
            }
        }
    }
}

fn python_references(manifest: &str, source: &str, references: &mut Vec<ManifestReference>) {
    let Ok(value) = toml::from_str::<TomlValue>(source) else {
        return;
    };
    let Some(scripts) = value
        .get("project")
        .and_then(|project| project.get("scripts"))
        .and_then(TomlValue::as_table)
    else {
        return;
    };
    let base = manifest_parent(manifest);
    for entrypoint in scripts.values().filter_map(TomlValue::as_str) {
        let module = entrypoint.split(':').next().unwrap_or_default();
        if module.is_empty()
            || !module
                .split('.')
                .all(|segment| !segment.is_empty() && segment.chars().all(valid_python_identifier))
        {
            continue;
        }
        let module_path = module.replace('.', "/");
        let candidates = [base.clone(), base.join("src")]
            .into_iter()
            .flat_map(|root| {
                [
                    root.join(format!("{module_path}.py")),
                    root.join(&module_path).join("__init__.py"),
                ]
            })
            .collect();
        push_reference(
            references,
            manifest,
            source,
            "Python script entry point",
            module,
            candidates,
        );
    }
}

fn valid_python_identifier(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}

fn contains_glob(path: &str) -> bool {
    path.contains(['*', '?', '[', ']'])
}

fn manifest_parent(manifest: &str) -> PathBuf {
    Path::new(manifest)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf()
}

fn push_reference(
    references: &mut Vec<ManifestReference>,
    manifest: &str,
    source: &str,
    kind: &'static str,
    target: &str,
    candidates: Vec<PathBuf>,
) {
    references.push(ManifestReference {
        manifest: manifest.to_owned(),
        line: source
            .lines()
            .position(|line| line.contains(target))
            .map_or(1, |index| index + 1),
        kind,
        target: target.to_owned(),
        candidates,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reports_only_literal_missing_manifest_paths() {
        let root = tempdir().expect("temporary repository");
        std::fs::create_dir_all(root.path().join("crates/present/src"))
            .expect("present package directory");
        std::fs::write(
            root.path().join("crates/present/Cargo.toml"),
            "[package]\nname = \"present\"\nversion = \"0.1.0\"\n",
        )
        .expect("present package manifest");
        let mut auxiliary = BTreeMap::from([(
            "Cargo.toml".to_owned(),
            "[workspace]\nmembers = [\"crates/present\", \"crates/missing\", \"plugins/*\"]\n\
             [dependencies]\npresent = { path = \"crates/present\" }\nmissing = { path = \"crates/missing\" }\n"
                .to_owned(),
        )]);
        auxiliary.extend(manifest_existence_markers(root.path(), &auxiliary));

        let findings = missing_manifest_paths(&auxiliary);

        assert_eq!(
            findings.len(),
            2,
            "auxiliary={auxiliary:#?}; references={:#?}",
            manifest_references(&auxiliary)
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.message.contains("crates/missing"))
        );
    }

    #[test]
    fn resolves_node_bins_and_python_entrypoints() {
        let root = tempdir().expect("temporary repository");
        std::fs::create_dir_all(root.path().join("bin")).expect("bin directory");
        std::fs::write(root.path().join("bin/tool.js"), "#!/usr/bin/env node\n")
            .expect("node executable");
        std::fs::create_dir_all(root.path().join("src/app")).expect("Python package");
        std::fs::write(root.path().join("src/app/cli.py"), "def main(): pass\n")
            .expect("Python entry point");
        let mut auxiliary = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"bin":{"tool":"bin/tool.js","missing":"bin/missing.js"}}"#.to_owned(),
            ),
            (
                "pyproject.toml".to_owned(),
                "[project.scripts]\napp = \"app.cli:main\"\nmissing = \"app.missing:main\"\n"
                    .to_owned(),
            ),
        ]);
        auxiliary.extend(manifest_existence_markers(root.path(), &auxiliary));

        let messages = missing_manifest_paths(&auxiliary)
            .into_iter()
            .map(|finding| finding.message)
            .collect::<Vec<_>>();

        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .any(|message| message.contains("bin/missing.js"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("app.missing"))
        );
    }

    #[test]
    fn ignores_manifest_contracts_inside_test_fixtures() {
        let auxiliary = BTreeMap::from([(
            "pnpr/.fixtures/packages/broken/package.json".to_owned(),
            r#"{"bin":"missing.js"}"#.to_owned(),
        )]);

        assert!(manifest_references(&auxiliary).is_empty());
        assert!(missing_manifest_paths(&auxiliary).is_empty());
    }
}
