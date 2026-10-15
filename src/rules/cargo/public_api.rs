use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use toml::Value;

use crate::findings::Finding;
use crate::source_analysis_context::SourceAnalysisContext;

use super::{CargoManifest, finding, manifest_directory};

pub(super) fn analyze(
    context: &SourceAnalysisContext<'_>,
    manifests: &[CargoManifest<'_>],
) -> Vec<Finding> {
    let libraries = manifests
        .iter()
        .filter(|manifest| is_library_manifest(context, manifest))
        .collect::<Vec<_>>();
    if libraries.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (path, _) in context
        .sources()
        .iter()
        .filter(|(path, _)| path.ends_with(".rs"))
    {
        let Some(owner) = owning_manifest(path, manifests) else {
            continue;
        };
        if !libraries.iter().any(|library| library.path == owner.path) {
            continue;
        }
        let masked = context.masked_lines(path).join("\n");
        append_public_anyhow_findings(path, &masked, &mut findings);
    }
    findings
}

fn is_library_manifest(context: &SourceAnalysisContext<'_>, manifest: &CargoManifest<'_>) -> bool {
    let Some(package) = manifest.value.get("package").and_then(Value::as_table) else {
        return false;
    };
    if !has_publication_intent(package) || package_has_binary_target(context, manifest) {
        return false;
    }
    if manifest
        .value
        .get("lib")
        .and_then(Value::as_table)
        .is_some()
    {
        return true;
    }
    context
        .sources()
        .contains_key(&default_source_path(manifest.path, "lib.rs"))
}

fn has_publication_intent(package: &toml::Table) -> bool {
    if package.get("publish").and_then(Value::as_bool) == Some(false)
        || package
            .get("publish")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        || package.get("version").and_then(Value::as_str) == Some("0.0.0")
    {
        return false;
    }
    let Some(description) = package.get("description").and_then(Value::as_str) else {
        return false;
    };
    if INTERNAL_CRATE_DESCRIPTION.is_match(description) {
        return false;
    }
    [
        "categories",
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

fn package_has_binary_target(
    context: &SourceAnalysisContext<'_>,
    manifest: &CargoManifest<'_>,
) -> bool {
    manifest
        .value
        .get("bin")
        .and_then(Value::as_array)
        .is_some_and(|targets| !targets.is_empty())
        || context
            .sources()
            .contains_key(&default_source_path(manifest.path, "main.rs"))
}

fn default_source_path(manifest_path: &str, name: &str) -> String {
    let directory = manifest_directory(manifest_path);
    if directory.is_empty() {
        format!("src/{name}")
    } else {
        format!("{directory}/src/{name}")
    }
}

fn owning_manifest<'a>(
    source_path: &str,
    manifests: &'a [CargoManifest<'a>],
) -> Option<&'a CargoManifest<'a>> {
    manifests
        .iter()
        .filter(|manifest| manifest.value.get("package").is_some())
        .filter(|manifest| source_belongs_to_manifest(source_path, manifest.path))
        .max_by_key(|manifest| manifest_directory(manifest.path).len())
}

fn source_belongs_to_manifest(source_path: &str, manifest_path: &str) -> bool {
    let directory = manifest_directory(manifest_path);
    directory.is_empty()
        || source_path
            .strip_prefix(directory)
            .is_some_and(|relative| relative.starts_with('/'))
}

fn append_public_anyhow_findings(path: &str, source: &str, findings: &mut Vec<Finding>) {
    let aliases = ANYHOW_ALIAS
        .captures_iter(source)
        .filter_map(|capture| capture.get(1).map(|name| name.as_str().to_owned()))
        .collect::<BTreeSet<_>>();
    for function in PUBLIC_FUNCTION.find_iter(source) {
        let Some(open) = source[function.end()..]
            .find('(')
            .map(|offset| function.end() + offset)
        else {
            continue;
        };
        let Some(close) = matching_parenthesis(source, open) else {
            continue;
        };
        let header_end = source[close + 1..]
            .find(['{', ';'])
            .map_or(source.len(), |offset| close + 1 + offset);
        let return_type = &source[close + 1..header_end];
        if !ANYHOW_RETURN.is_match(return_type)
            && !RETURN_TYPE.captures(return_type).is_some_and(|capture| {
                capture
                    .get(1)
                    .is_some_and(|name| aliases.contains(name.as_str()))
            })
        {
            continue;
        }
        let line = source[..function.start()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        findings.push(finding(
            "rust-public-anyhow-result",
            path,
            line,
            "public library function exposes an opaque anyhow error".to_owned(),
        ));
    }
}

fn matching_parenthesis(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

static INTERNAL_CRATE_DESCRIPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\binternal (?:component )?crate\b").unwrap());
static ANYHOW_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?type[ \t]+([A-Za-z_]\w*)(?:[ \t]*<[^;=]+>)?[ \t]*=[ \t]*(?:anyhow::Result\b|Result[ \t]*<[^;]*anyhow::Error)",
    )
    .unwrap()
});
static PUBLIC_FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*pub[ \t]+(?:(?:async|const|unsafe)[ \t]+|extern(?:[ \t]+[^\s]+)?[ \t]+)*fn[ \t]+[A-Za-z_]\w*",
    )
    .unwrap()
});
static ANYHOW_RETURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)->\s*(?:anyhow::Result\b|anyhow::Error\b|Result\s*<[^>{};]*anyhow::Error)")
        .unwrap()
});
static RETURN_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)->\s*([A-Za-z_]\w*)\b").unwrap());

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn reports_direct_and_locally_aliased_anyhow_in_public_library_apis() {
        let findings = analyze_project(
            [(
                "Cargo.toml",
                "[package]\nname = \"lib\"\nversion = \"1.0.0\"\ndescription = \"Published library\"\nlicense = \"MIT\"\nrust-version = \"1.85\"",
            )],
            [(
                "src/lib.rs",
                "pub type AppResult<T> = anyhow::Result<T>;\n\npub async fn direct(\n    value: usize,\n) -> anyhow::Result<usize> { todo!() }\n\npub fn aliased() -> AppResult<()> { todo!() }\n\npub(crate) fn crate_only() -> anyhow::Result<()> { todo!() }\nfn private() -> anyhow::Result<()> { todo!() }\npub fn typed() -> Result<(), DomainError> { todo!() }",
            )],
        );

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("rust-public-anyhow-result", 3),
                ("rust-public-anyhow-result", 7),
            ]
        );
    }

    #[test]
    fn ignores_public_anyhow_functions_owned_only_by_a_binary() {
        let findings = analyze_project(
            [(
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"1.0.0\"\ndescription = \"Application\"\nlicense = \"MIT\"\nrust-version = \"1.85\"",
            )],
            [(
                "src/main.rs",
                "pub fn run() -> anyhow::Result<()> { Ok(()) }",
            )],
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn assigns_nested_sources_to_the_nearest_manifest() {
        let findings = analyze_project(
            [
                (
                    "Cargo.toml",
                    "[package]\nname = \"root\"\nversion = \"1.0.0\"\ndescription = \"Published library\"\nlicense = \"MIT\"\nrust-version = \"1.85\"",
                ),
                (
                    "tool/Cargo.toml",
                    "[package]\nname = \"tool\"\nversion = \"1.0.0\"\ndescription = \"Application\"\nlicense = \"MIT\"\nrust-version = \"1.85\"",
                ),
            ],
            [
                (
                    "src/lib.rs",
                    "pub fn root() -> anyhow::Result<()> { Ok(()) }",
                ),
                (
                    "tool/src/main.rs",
                    "pub fn tool() -> anyhow::Result<()> { Ok(()) }",
                ),
            ],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "src/lib.rs");
    }

    #[test]
    fn ignores_internal_library_packages() {
        let findings = analyze_project(
            [
                (
                    "private/Cargo.toml",
                    "[package]\nname = \"private\"\nversion = \"1.0.0\"\npublish = false\ndescription = \"Private library\"\nlicense = \"MIT\"",
                ),
                (
                    "zero/Cargo.toml",
                    "[package]\nname = \"zero\"\nversion = \"0.0.0\"\ndescription = \"Workspace library\"\nlicense = \"MIT\"",
                ),
                (
                    "internal/Cargo.toml",
                    "[package]\nname = \"internal\"\nversion = \"1.2.3\"\ndescription = \"An internal component crate of the app\"\nlicense = \"MIT\"",
                ),
            ],
            [
                (
                    "private/src/lib.rs",
                    "pub fn run() -> anyhow::Result<()> { Ok(()) }",
                ),
                (
                    "zero/src/lib.rs",
                    "pub fn run() -> anyhow::Result<()> { Ok(()) }",
                ),
                (
                    "internal/src/lib.rs",
                    "pub fn run() -> anyhow::Result<()> { Ok(()) }",
                ),
            ],
        );

        assert!(findings.is_empty());
    }

    fn analyze_project<const A: usize, const S: usize>(
        files: [(&str, &str); A],
        source_files: [(&str, &str); S],
    ) -> Vec<Finding> {
        let auxiliary = files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let sources = source_files
            .into_iter()
            .map(|(path, source)| (path.to_owned(), source.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let base = BTreeMap::new();
        let changed = BTreeSet::new();
        let context =
            SourceAnalysisContext::with_auxiliary(&sources, &base, &changed, false, &auxiliary);
        let manifests = super::super::parse_manifests(&context);
        analyze(&context, &manifests)
    }
}
