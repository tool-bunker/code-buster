use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::findings::{Finding, Severity};

pub fn analyze(root: &Path, sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = re_export_findings(sources);
    let privacy = PackagePrivacy::from_auxiliary(&package_manifests(root, sources));
    if privacy.has_private_packages() {
        findings.extend(dead_export_findings(sources, &privacy));
    }
    findings
}

fn package_manifests(root: &Path, sources: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut candidates = BTreeSet::<PathBuf>::new();
    for source_path in sources.keys() {
        let mut directory = Path::new(source_path).parent();
        while let Some(relative) = directory {
            for manifest in ["Cargo.toml", "package.json"] {
                candidates.insert(relative.join(manifest));
            }
            if relative.as_os_str().is_empty() {
                break;
            }
            directory = relative.parent();
        }
    }
    candidates
        .into_iter()
        .filter_map(|relative| {
            fs::read_to_string(root.join(&relative))
                .ok()
                .map(|source| (relative.to_string_lossy().replace('\\', "/"), source))
        })
        .collect()
}

#[derive(Default)]
struct PackagePrivacy {
    rust: Vec<(String, bool)>,
    javascript: Vec<(String, bool)>,
}

impl PackagePrivacy {
    fn from_auxiliary(auxiliary: &BTreeMap<String, String>) -> Self {
        let mut privacy = Self::default();
        for (path, source) in auxiliary {
            if let Some(root) = manifest_root(path, "Cargo.toml") {
                privacy.rust.push((root, cargo_package_is_private(source)));
            } else if let Some(root) = manifest_root(path, "package.json") {
                privacy
                    .javascript
                    .push((root, node_package_is_private(source)));
            }
        }
        privacy.rust.sort_by_key(|entry| Reverse(entry.0.len()));
        privacy
            .javascript
            .sort_by_key(|entry| Reverse(entry.0.len()));
        privacy
    }

    fn has_private_packages(&self) -> bool {
        self.rust
            .iter()
            .chain(&self.javascript)
            .any(|(_, private)| *private)
    }

    fn source_is_private(&self, path: &str) -> bool {
        let packages = if path.ends_with(".rs") {
            &self.rust
        } else {
            &self.javascript
        };
        packages
            .iter()
            .find(|(root, _)| path_is_below(root, path))
            .is_some_and(|(_, private)| *private)
    }
}

fn manifest_root(path: &str, manifest: &str) -> Option<String> {
    path.strip_suffix(manifest)
        .map(|root| root.trim_end_matches('/').to_owned())
}

fn path_is_below(root: &str, path: &str) -> bool {
    root.is_empty()
        || path
            .strip_prefix(root)
            .is_some_and(|relative| relative.starts_with('/'))
}

fn cargo_package_is_private(source: &str) -> bool {
    let mut in_package = false;
    for line in source.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package
            && line
                .split_once('=')
                .is_some_and(|(key, value)| key.trim() == "publish" && value.trim() == "false")
        {
            return true;
        }
    }
    false
}

#[derive(serde::Deserialize)]
struct NodePackagePrivacy {
    #[serde(default)]
    private: bool,
}

fn node_package_is_private(source: &str) -> bool {
    serde_json::from_str::<NodePackagePrivacy>(source).is_ok_and(|package| package.private)
}

fn re_export_findings(sources: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, source) in sources {
        for (index, line) in source.split('\n').enumerate() {
            if is_re_export(path, line.trim())
                && let Some(finding) = finding(
                    "re-export",
                    path,
                    index + 1,
                    "module API is forwarded through a re-export facade",
                    "medium",
                )
            {
                findings.push(finding);
            }
        }
    }
    findings
}

fn is_re_export(path: &str, line: &str) -> bool {
    path.ends_with(".rs") && line.starts_with("pub use ")
        || path.ends_with(".dart") && line.starts_with("export ")
        || matches!(
            path.rsplit_once('.').map(|(_, extension)| extension),
            Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
        ) && (line.starts_with("export *")
            || line.starts_with("export {") && line.contains(" from "))
}

fn dead_export_findings(
    sources: &BTreeMap<String, String>,
    privacy: &PackagePrivacy,
) -> Vec<Finding> {
    let declarations = sources
        .iter()
        .filter(|(path, _)| privacy.source_is_private(path))
        .flat_map(|(path, source)| {
            source
                .split('\n')
                .enumerate()
                .filter_map(move |(index, line)| {
                    exported_declaration_name(path, line.trim())
                        .map(|name| (path.as_str(), index + 1, name))
                })
        })
        .collect::<Vec<_>>();

    declarations
        .into_iter()
        .filter(|(_, _, name)| !matches!(*name, "main" | "run"))
        .filter(|(_, _, name)| identifier_occurrences(sources, name) == 1)
        .filter_map(|(path, line, name)| {
            finding(
                "dead-export",
                path,
                line,
                &format!("`{name}` is exported but has no repository-local references"),
                "low",
            )
        })
        .collect()
}

fn exported_declaration_name<'a>(path: &str, line: &'a str) -> Option<&'a str> {
    let declaration = if path.ends_with(".rs") {
        line.strip_prefix("pub ")?
    } else if matches!(
        path.rsplit_once('.').map(|(_, extension)| extension),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    ) {
        let declaration = line.strip_prefix("export ")?;
        declaration.strip_prefix("default ").unwrap_or(declaration)
    } else {
        return None;
    };
    let declaration = declaration
        .strip_prefix("async ")
        .or_else(|| declaration.strip_prefix("unsafe "))
        .unwrap_or(declaration);
    for prefix in [
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "const ",
        "static ",
        "type ",
        "function ",
        "class ",
        "interface ",
        "let ",
        "var ",
    ] {
        if let Some(rest) = declaration.strip_prefix(prefix) {
            let name_end = rest
                .bytes()
                .position(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
                .unwrap_or(rest.len());
            return (name_end > 0).then(|| &rest[..name_end]);
        }
    }
    None
}

fn identifier_occurrences(sources: &BTreeMap<String, String>, name: &str) -> usize {
    sources
        .values()
        .map(|source| {
            source
                .match_indices(name)
                .filter(|(index, _)| {
                    let bytes = source.as_bytes();
                    let before = index
                        .checked_sub(1)
                        .and_then(|index| bytes.get(index))
                        .copied();
                    let after = bytes.get(index + name.len()).copied();
                    before.is_none_or(identifier_boundary) && after.is_none_or(identifier_boundary)
                })
                .count()
        })
        .sum()
}

fn identifier_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && byte != b'_'
}

fn finding(
    code: &str,
    path: &str,
    line: usize,
    message: &str,
    confidence: &str,
) -> Option<Finding> {
    let metadata = crate::rule_catalog::metadata(code)?;
    Some(Finding {
        code: code.to_owned(),
        severity: Severity::parse(metadata.default_severity)?,
        path: path.to_owned(),
        line,
        end_line: line,
        message: message.to_owned(),
        confidence: confidence.to_owned(),
        why: metadata.why.to_owned(),
        suggestion: metadata.suggestion.to_owned(),
        related_files: Vec::new(),
        snippet: String::new(),
        code_flow: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{PackagePrivacy, dead_export_findings, re_export_findings};

    #[test]
    fn reports_re_exports_for_supported_module_syntaxes() {
        let sources = BTreeMap::from([
            (
                "lib.rs".to_owned(),
                "pub use crate::api::Client;".to_owned(),
            ),
            (
                "index.ts".to_owned(),
                "export { Button } from './button';".to_owned(),
            ),
            ("models.dart".to_owned(), "export 'user.dart';".to_owned()),
        ]);

        let findings = re_export_findings(&sources);

        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|finding| finding.code == "re-export"));
    }

    #[test]
    fn reports_only_exports_without_repository_local_references() {
        let sources = BTreeMap::from([
            (
                "lib.rs".to_owned(),
                "pub fn orphaned() {}\npub fn used() {}\nfn caller() { used(); }".to_owned(),
            ),
            (
                "index.ts".to_owned(),
                "export class Lonely {}\nexport function called() {}\ncalled();".to_owned(),
            ),
        ]);
        let privacy = PackagePrivacy::from_auxiliary(&BTreeMap::from([
            (
                "Cargo.toml".to_owned(),
                "[package]\nname = \"private\"\npublish = false".to_owned(),
            ),
            ("package.json".to_owned(), r#"{"private": true}"#.to_owned()),
        ]));

        let findings = dead_export_findings(&sources, &privacy);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![("index.ts", 1), ("lib.rs", 1)]
        );
    }

    #[test]
    fn scopes_private_exports_to_the_nearest_package_manifest() {
        let sources = BTreeMap::from([
            (
                "src/public.rs".to_owned(),
                "pub fn public_root() {}".to_owned(),
            ),
            (
                "crates/tool/src/lib.rs".to_owned(),
                "pub fn private_rust() {}".to_owned(),
            ),
            (
                "web/public.ts".to_owned(),
                "export function publicNode() {}".to_owned(),
            ),
            (
                "web/packages/tool/index.ts".to_owned(),
                "export function privateNode() {}".to_owned(),
            ),
        ]);
        let privacy = PackagePrivacy::from_auxiliary(&BTreeMap::from([
            (
                "Cargo.toml".to_owned(),
                "[package]\nname = \"public\"".to_owned(),
            ),
            (
                "crates/tool/Cargo.toml".to_owned(),
                "[package]\nname = \"tool\"\npublish = false".to_owned(),
            ),
            ("web/package.json".to_owned(), "{}".to_owned()),
            (
                "web/packages/tool/package.json".to_owned(),
                r#"{"private": true}"#.to_owned(),
            ),
        ]));

        let findings = dead_export_findings(&sources, &privacy);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.path.as_str())
                .collect::<Vec<_>>(),
            ["crates/tool/src/lib.rs", "web/packages/tool/index.ts"]
        );
    }
}
