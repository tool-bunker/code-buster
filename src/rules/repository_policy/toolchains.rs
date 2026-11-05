use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::findings::Finding;

use super::finding;

const TOOLCHAIN_DRIFT: &str = "toolchain-version-drift";

static NODE_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*node-version\s*:\s*[\"']?([^\s\"'#\[\]{]+)"#)
        .expect("Node CI version regex must compile")
});
static PYTHON_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*python-version\s*:\s*[\"']?([^\s\"'#\[\]{]+)"#)
        .expect("Python CI version regex must compile")
});
static JAVA_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*java-version\s*:\s*[\"']?([0-9]+(?:\.[0-9]+){0,2})[\"']?\s*$"#)
        .expect("Java CI version regex must compile")
});
static MAVEN_JAVA_REQUIREMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)<(?:maven\.compiler\.release|maven\.compiler\.source|java\.version)>\s*([0-9]+(?:\.[0-9]+)?)\s*</",
    )
    .expect("Maven Java requirement regex must compile")
});
static RUST_TOOLCHAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*toolchain\s*:\s*[\"']?([0-9]+(?:\.[0-9]+){1,2})[\"']?\s*$"#)
        .expect("Rust CI toolchain regex must compile")
});

pub(super) fn analyze(auxiliary: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_node(auxiliary, &mut findings);
    check_python(auxiliary, &mut findings);
    check_rust(auxiliary, &mut findings);
    check_java(auxiliary, &mut findings);
    findings
}

fn check_node(auxiliary: &BTreeMap<String, String>, findings: &mut Vec<Finding>) {
    let Some(package) = auxiliary.get("package.json") else {
        return;
    };
    let Ok(value) = serde_json::from_str::<JsonValue>(package) else {
        return;
    };
    let Some(requirement) = value
        .get("engines")
        .and_then(|engines| engines.get("node"))
        .and_then(JsonValue::as_str)
    else {
        return;
    };
    for pin in pins(auxiliary, &[".nvmrc", ".node-version"], &NODE_VERSION) {
        report_disallowed("Node.js", requirement, pin, findings);
    }
}

fn check_python(auxiliary: &BTreeMap<String, String>, findings: &mut Vec<Finding>) {
    let Some(pyproject) = auxiliary.get("pyproject.toml") else {
        return;
    };
    let Ok(value) = toml::from_str::<TomlValue>(pyproject) else {
        return;
    };
    let Some(requirement) = value
        .get("project")
        .and_then(|project| project.get("requires-python"))
        .and_then(TomlValue::as_str)
    else {
        return;
    };
    for pin in pins(auxiliary, &[".python-version"], &PYTHON_VERSION) {
        if !pin_matches_nested_python_project(&pin, auxiliary) {
            report_disallowed("Python", requirement, pin, findings);
        }
    }
}

fn pin_matches_nested_python_project(pin: &Pin<'_>, auxiliary: &BTreeMap<String, String>) -> bool {
    is_ci_path(&pin.path)
        && auxiliary.iter().any(|(path, source)| {
            let Some(parent) = path.strip_suffix("/pyproject.toml") else {
                return false;
            };
            if !pin.source.contains(parent) {
                return false;
            }
            let Ok(project) = toml::from_str::<TomlValue>(source) else {
                return false;
            };
            project
                .get("project")
                .and_then(|project| project.get("requires-python"))
                .and_then(TomlValue::as_str)
                .is_some_and(|requirement| {
                    constraint_allows(requirement, pin.version) != Some(false)
                })
        })
}
fn check_java(auxiliary: &BTreeMap<String, String>, findings: &mut Vec<Finding>) {
    let Some(pom) = auxiliary.get("pom.xml") else {
        return;
    };
    let Some(requirement) = MAVEN_JAVA_REQUIREMENT
        .captures(pom)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str())
        .and_then(java_version)
    else {
        return;
    };
    for pin in java_pins(auxiliary) {
        report_disallowed(
            "Java",
            &format!(">={}.{}", requirement.major, requirement.minor),
            pin,
            findings,
        );
    }
}

fn java_pins(auxiliary: &BTreeMap<String, String>) -> Vec<Pin<'_>> {
    let mut pins = Vec::new();
    if let Some(source) = auxiliary.get(".java-version")
        && let Some((index, raw)) = source
            .lines()
            .enumerate()
            .find(|(_, line)| !line.trim().is_empty())
        && let Some(version) = java_version(raw)
    {
        pins.push(Pin {
            path: ".java-version".to_owned(),
            source,
            raw: raw.trim().to_owned(),
            version,
            line: index + 1,
        });
    }
    for (path, source) in auxiliary.iter().filter(|(path, _)| is_ci_path(path)) {
        for capture in JAVA_VERSION.captures_iter(source) {
            let Some(raw) = capture.get(1) else {
                continue;
            };
            if let Some(version) = java_version(raw.as_str()) {
                pins.push(Pin {
                    path: path.to_owned(),
                    source,
                    raw: raw.as_str().to_owned(),
                    version,
                    line: line_at(source, raw.start()),
                });
            }
        }
    }
    pins
}

fn java_version(raw: &str) -> Option<Version> {
    let parsed = Version::parse(raw)?;
    if parsed.major == 1 && parsed.minor > 0 {
        return Some(Version {
            major: parsed.minor,
            minor: 0,
            patch: 0,
            components: 1,
        });
    }
    Some(parsed)
}

fn check_rust(auxiliary: &BTreeMap<String, String>, findings: &mut Vec<Finding>) {
    let Some(cargo) = auxiliary.get("Cargo.toml") else {
        return;
    };
    let Ok(value) = toml::from_str::<TomlValue>(cargo) else {
        return;
    };
    let requirement = value
        .get("package")
        .and_then(|package| package.get("rust-version"))
        .or_else(|| {
            value
                .get("workspace")
                .and_then(|workspace| workspace.get("package"))
                .and_then(|package| package.get("rust-version"))
        })
        .and_then(TomlValue::as_str);
    let Some(requirement) = requirement else {
        return;
    };
    let mut rust_pins = pins(auxiliary, &[], &RUST_TOOLCHAIN);
    rust_pins.retain(|pin| {
        pin.path == "rust-toolchain.toml"
            || ["rust", "cargo", "Rust", "Cargo"]
                .iter()
                .any(|marker| pin.source.contains(marker))
    });
    if let Some(source) = auxiliary.get("rust-toolchain.toml")
        && let Ok(toolchain) = toml::from_str::<TomlValue>(source)
        && let Some(raw) = toolchain
            .get("toolchain")
            .and_then(|toolchain| toolchain.get("channel"))
            .and_then(TomlValue::as_str)
        && let Some(version) = Version::parse(raw)
    {
        rust_pins.push(Pin {
            path: "rust-toolchain.toml".to_owned(),
            source,
            raw: raw.to_owned(),
            version,
            line: source
                .lines()
                .position(|line| line.contains(raw))
                .map_or(1, |index| index + 1),
        });
    }
    for pin in rust_pins {
        report_disallowed("Rust", &format!(">={requirement}"), pin, findings);
    }
}

fn report_disallowed(
    toolchain: &str,
    requirement: &str,
    pin: Pin<'_>,
    findings: &mut Vec<Finding>,
) {
    if constraint_allows(requirement, pin.version) != Some(false) {
        return;
    }
    findings.push(finding(
        TOOLCHAIN_DRIFT,
        &pin.path,
        pin.line,
        format!(
            "{toolchain} toolchain pin {} does not satisfy manifest requirement {requirement}",
            pin.raw
        ),
        Vec::new(),
    ));
}

struct Pin<'a> {
    path: String,
    source: &'a str,
    raw: String,
    version: Version,
    line: usize,
}

fn pins<'a>(
    auxiliary: &'a BTreeMap<String, String>,
    files: &[&str],
    ci_pattern: &Regex,
) -> Vec<Pin<'a>> {
    let mut pins = files
        .iter()
        .filter_map(|path| {
            let source = auxiliary.get(*path)?;
            let (index, raw) = source
                .lines()
                .enumerate()
                .find(|(_, line)| !line.trim().is_empty())?;
            let raw = raw.trim();
            Some(Pin {
                path: (*path).to_owned(),
                source,
                raw: raw.to_owned(),
                version: Version::parse(raw)?,
                line: index + 1,
            })
        })
        .collect::<Vec<_>>();
    for (path, source) in auxiliary.iter().filter(|(path, _)| is_ci_path(path)) {
        for capture in ci_pattern.captures_iter(source) {
            let Some(raw) = capture.get(1) else {
                continue;
            };
            if let Some(version) = Version::parse(raw.as_str()) {
                pins.push(Pin {
                    path: path.to_owned(),
                    source,
                    raw: raw.as_str().to_owned(),
                    version,
                    line: line_at(source, raw.start()),
                });
            }
        }
    }
    pins
}

fn line_at(source: &str, offset: usize) -> usize {
    1 + source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    components: usize,
}

impl Version {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw
            .trim()
            .trim_matches(['\'', '"'])
            .trim_start_matches(['v', '=']);
        let numeric = raw.split('-').next()?;
        let parts = numeric
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>();
        let parts = parts.ok()?;
        if parts.is_empty() || parts.len() > 3 {
            return None;
        }
        Some(Self {
            major: parts[0],
            minor: *parts.get(1).unwrap_or(&0),
            patch: *parts.get(2).unwrap_or(&0),
            components: parts.len(),
        })
    }

    fn cmp_value(self, other: Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

fn constraint_allows(requirement: &str, version: Version) -> Option<bool> {
    if requirement.contains("||") || requirement.contains("~=") {
        return None;
    }
    let normalized = requirement.replace(',', " ");
    let mut checked = false;
    for token in normalized.split_ascii_whitespace() {
        let allowed = constraint_token_allows(token, version)?;
        checked = true;
        if !allowed {
            return Some(false);
        }
    }
    checked.then_some(true)
}

fn constraint_token_allows(token: &str, version: Version) -> Option<bool> {
    let (operator, raw) = [">=", "<=", ">", "<", "^", "~", "="]
        .iter()
        .find_map(|operator| token.strip_prefix(operator).map(|raw| (*operator, raw)))
        .unwrap_or(("", token));
    let expected = Version::parse(raw.trim_end_matches(['x', 'X', '*']))?;
    if partial_channel_overlaps_requirement(version, expected) {
        return None;
    }
    let comparison = version.cmp_value(expected);
    match operator {
        ">=" => Some(comparison != Ordering::Less),
        ">" => Some(comparison == Ordering::Greater),
        "<=" => Some(comparison != Ordering::Greater),
        "<" => Some(comparison == Ordering::Less),
        "^" => Some(version.major == expected.major && comparison != Ordering::Less),
        "~" if expected.components >= 2 => Some(
            version.major == expected.major
                && version.minor == expected.minor
                && comparison != Ordering::Less,
        ),
        "~" => Some(version.major == expected.major && comparison != Ordering::Less),
        "" | "=" if expected.components == 1 => Some(version.major == expected.major),
        "" | "=" => Some(comparison == Ordering::Equal),
        _ => None,
    }
}

fn partial_channel_overlaps_requirement(version: Version, expected: Version) -> bool {
    version.components < expected.components
        && version.major == expected.major
        && (version.components == 1 || version.minor == expected.minor)
}

fn is_ci_path(path: &str) -> bool {
    path == ".gitlab-ci.yml"
        || path == "azure-pipelines.yml"
        || path == "Jenkinsfile"
        || (path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_node_python_and_rust_pins_outside_manifest_constraints() {
        let files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"engines":{"node":">=20 <23"}}"#.to_owned(),
            ),
            (".nvmrc".to_owned(), "18.20.0\n".to_owned()),
            (
                "pyproject.toml".to_owned(),
                "[project]\nrequires-python = \">=3.11\"\n".to_owned(),
            ),
            (".python-version".to_owned(), "3.10.14\n".to_owned()),
            (
                "Cargo.toml".to_owned(),
                "[package]\nname='x'\nrust-version='1.88'\n".to_owned(),
            ),
            (
                "rust-toolchain.toml".to_owned(),
                "[toolchain]\nchannel='1.87.0'\n".to_owned(),
            ),
        ]);
        let findings = analyze(&files);
        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code == TOOLCHAIN_DRIFT)
        );
    }

    #[test]
    fn accepts_compatible_pins_and_ignores_dynamic_ci_matrices() {
        let files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"engines":{"node":">=20 <23"}}"#.to_owned(),
            ),
            (".nvmrc".to_owned(), "22.1.0\n".to_owned()),
            (
                "pyproject.toml".to_owned(),
                "[project]\nrequires-python = \">=3.11\"\n".to_owned(),
            ),
            (".python-version".to_owned(), "3.12\n".to_owned()),
            (
                ".github/workflows/ci.yml".to_owned(),
                "node-version: ${{ matrix.node }}\npython-version: ${{ matrix.python }}\n"
                    .to_owned(),
            ),
        ]);
        assert!(analyze(&files).is_empty());
    }

    #[test]
    fn associates_ci_python_pins_with_explicitly_referenced_nested_projects() {
        let files = BTreeMap::from([
            (
                "pyproject.toml".to_owned(),
                "[project]\nrequires-python = \"==3.14.7\"\n".to_owned(),
            ),
            (
                "rust/parser/pyproject.toml".to_owned(),
                "[project]\nrequires-python = \">=3.12\"\n".to_owned(),
            ),
            (
                ".github/workflows/parser.yml".to_owned(),
                "python-version: 3.12.10\nrun: maturin build --manifest-path rust/parser/Cargo.toml\n"
                    .to_owned(),
            ),
        ]);
        assert!(analyze(&files).is_empty());
    }

    #[test]
    fn treats_partial_toolchain_channels_as_ranges_and_reports_the_matched_line() {
        let mut files = BTreeMap::from([
            (
                "package.json".to_owned(),
                r#"{"engines":{"node":">=20.9.0 <23"}}"#.to_owned(),
            ),
            (".node-version".to_owned(), "v20\n".to_owned()),
            (
                ".github/workflows/ci.yml".to_owned(),
                "env:\n  BASELINE: 20\nnode-version: 20\n".to_owned(),
            ),
        ]);
        assert!(analyze(&files).is_empty());
        assert_eq!(
            constraint_allows(">=20.9.0", Version::parse("20").unwrap()),
            None
        );

        files.insert(
            "package.json".to_owned(),
            r#"{"engines":{"node":">=21"}}"#.to_owned(),
        );
        let findings = analyze(&files);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings
                .iter()
                .find(|finding| finding.path == ".github/workflows/ci.yml")
                .map(|finding| finding.line),
            Some(3)
        );
    }

    #[test]
    fn evaluates_simple_conjunctions_conservatively() {
        assert_eq!(
            constraint_allows(">=20 <23", Version::parse("22.1").unwrap()),
            Some(true)
        );
        assert_eq!(
            constraint_allows(">=20 <23", Version::parse("23.0").unwrap()),
            Some(false)
        );
        assert_eq!(
            constraint_allows("20 || 22", Version::parse("21").unwrap()),
            None
        );
    }

    #[test]
    fn reports_java_pins_below_maven_release_and_accepts_newer_jdks() {
        let mut files = BTreeMap::from([
            (
                "pom.xml".to_owned(),
                "<properties><maven.compiler.release>17</maven.compiler.release></properties>"
                    .to_owned(),
            ),
            (".java-version".to_owned(), "11\n".to_owned()),
        ]);
        let findings = analyze(&files);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Java toolchain pin 11"));

        files.insert(".java-version".to_owned(), "21\n".to_owned());
        assert!(analyze(&files).is_empty());
    }
}
