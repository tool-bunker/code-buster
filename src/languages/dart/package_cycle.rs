use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::findings::{Finding, Severity};
use crate::rule_catalog;

use super::index::DartSourceIndex;

#[cfg(test)]
pub(crate) fn analyze(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    analyze_sources(
        sources
            .iter()
            .filter(|(path, _)| path.ends_with(".dart"))
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect(),
    )
}

pub(crate) fn analyze_index(index: &DartSourceIndex<'_>) -> Vec<Finding> {
    analyze_sources(
        index
            .paths()
            .map(|path| (path, index.source(path)))
            .collect(),
    )
}

fn analyze_sources(sources: Vec<(&str, &str)>) -> Vec<Finding> {
    let owners = sources
        .iter()
        .map(|(path, _)| owner(path))
        .filter(|owner| !owner.is_empty())
        .collect::<BTreeSet<_>>();
    if owners.len() < 2 {
        return Vec::new();
    }
    let mut edges = owners
        .iter()
        .map(|owner| (owner.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for (path, source) in sources {
        let source_owner = owner(path);
        for capture in PACKAGE_DIRECTIVE.captures_iter(source) {
            let target = capture
                .get(1)
                .expect("package import owner capture")
                .as_str();
            if target != source_owner && owners.contains(target) {
                let Some(source_edges) = edges.get_mut(&source_owner) else {
                    continue;
                };
                source_edges.insert(target.to_owned());
            }
        }
    }
    let metadata = rule_catalog::metadata("dart-package-cycle")
        .expect("Dart package cycle metadata must exist");
    cycles(&edges)
        .into_iter()
        .map(|cycle| Finding {
            code: "dart-package-cycle".to_owned(),
            severity: Severity::Warn,
            path: cycle[0].clone(),
            line: 1,
            end_line: 0,
            message: format!("Dart package cycle: {}", cycle.join(" -> ")),
            confidence: "high".to_owned(),
            why: metadata.why.to_owned(),
            suggestion: metadata.suggestion.to_owned(),
            related_files: cycle[1..cycle.len() - 1].to_vec(),
            snippet: String::new(),
            code_flow: Vec::new(),
        })
        .collect()
}

fn owner(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let segments = normalized.split('/').collect::<Vec<_>>();
    if let Some(packages) = segments.iter().position(|segment| *segment == "packages")
        && let Some(package) = segments.get(packages + 1)
    {
        return (*package).to_owned();
    }
    segments
        .iter()
        .rposition(|segment| *segment == "lib")
        .filter(|index| *index > 0)
        .map_or_else(|| "root".to_owned(), |index| segments[index - 1].to_owned())
}

// code-buster-ignore complex-function: depth-first cycle detection keeps stack and canonicalization state local.
fn cycles(edges: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    fn visit(
        node: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
        emitted: &mut BTreeSet<String>,
        result: &mut Vec<Vec<String>>,
    ) {
        if visiting.contains(node) {
            if let Some(index) = stack.iter().position(|entry| entry == node) {
                let mut cycle = stack[index..].to_vec();
                cycle.push(node.to_owned());
                let mut canonical = cycle[..cycle.len() - 1].to_vec();
                canonical.sort();
                if emitted.insert(canonical.join("|")) {
                    result.push(cycle);
                }
            }
            return;
        }
        if !visited.insert(node.to_owned()) {
            return;
        }
        visiting.insert(node.to_owned());
        stack.push(node.to_owned());
        if let Some(dependencies) = edges.get(node) {
            for dependency in dependencies {
                visit(dependency, edges, visiting, visited, stack, emitted, result);
            }
        }
        stack.pop();
        visiting.remove(node);
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = Vec::new();
    let mut emitted = BTreeSet::new();
    let mut result = Vec::new();
    for node in edges.keys() {
        visit(
            node,
            edges,
            &mut visiting,
            &mut visited,
            &mut stack,
            &mut emitted,
            &mut result,
        );
    }
    result
}

static PACKAGE_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^\s*(?:import|export)\s+[\s\S]*?['\"]package:([^/'\"]+)/[^'\"]*['\"][\s\S]*?;"#,
    )
    .expect("Dart package directive regex")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_each_package_cycle_once() {
        let sources = BTreeMap::from([
            (
                "packages/alpha/lib/alpha.dart".to_owned(),
                "import 'package:beta/beta.dart';\n".to_owned(),
            ),
            (
                "packages/beta/lib/beta.dart".to_owned(),
                "export 'package:alpha/alpha.dart';\n".to_owned(),
            ),
        ]);

        let findings = analyze(&sources);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "alpha");
        assert_eq!(
            findings[0].message,
            "Dart package cycle: alpha -> beta -> alpha"
        );
        assert_eq!(findings[0].related_files, ["beta"]);
    }

    #[test]
    fn ignores_imports_from_sources_without_a_package_owner() {
        let sources = BTreeMap::from([
            (
                "packages/alpha/lib/alpha.dart".to_owned(),
                "import 'package:beta/beta.dart';\n".to_owned(),
            ),
            (
                "packages/beta/lib/beta.dart".to_owned(),
                "import 'package:alpha/alpha.dart';\n".to_owned(),
            ),
            (
                "packages/".to_owned(),
                "import 'package:alpha/alpha.dart';\n".to_owned(),
            ),
        ]);

        let findings = analyze(&sources);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "Dart package cycle: alpha -> beta -> alpha"
        );
    }
}
