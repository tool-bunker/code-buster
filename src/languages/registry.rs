use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone, Copy, Debug)]
pub struct Language {
    pub id: &'static str,
    aliases: &'static [&'static str],
    extensions: &'static [&'static str],
}

impl Language {
    fn matches(self, value: &str) -> bool {
        self.id == value || self.aliases.contains(&value)
    }

    pub fn owns_extension(self, extension: &str) -> bool {
        self.extensions.contains(&extension)
    }
}

const HTML: Language = Language {
    id: "html",
    aliases: &["htm"],
    extensions: &[".html", ".htm", ".svelte"],
};
const CSS: Language = Language {
    id: "css",
    aliases: &[],
    extensions: &[".css"],
};
const FRONTEND_LANGUAGES: &[Language] = &[HTML, CSS];

pub const LANGUAGES: &[Language] = &[
    Language {
        id: "cpp",
        aliases: &["c++"],
        extensions: &[".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"],
    },
    Language {
        id: "objective-c",
        aliases: &["objc", "objectivec"],
        extensions: &[".m", ".mm"],
    },
    Language {
        id: "csharp",
        aliases: &["cs"],
        extensions: &[".cs"],
    },
    Language {
        id: "dart",
        aliases: &[],
        extensions: &[".dart"],
    },
    Language {
        id: "rust",
        aliases: &["rs"],
        extensions: &[".rs"],
    },
    Language {
        id: "mojo",
        aliases: &[],
        extensions: &[".mojo"],
    },
    Language {
        id: "odin",
        aliases: &["odinlang"],
        extensions: &[".odin"],
    },
    Language {
        id: "nim",
        aliases: &[],
        extensions: &[".nim", ".nims"],
    },
    Language {
        id: "python",
        aliases: &["py"],
        extensions: &[".py"],
    },
    Language {
        id: "javascript",
        aliases: &["js"],
        extensions: &[".js", ".jsx", ".mjs", ".cjs"],
    },
    Language {
        id: "typescript",
        aliases: &["ts"],
        extensions: &[".ts", ".tsx", ".mts", ".cts"],
    },
    Language {
        id: "go",
        aliases: &["golang"],
        extensions: &[".go", ".mod"],
    },
    HTML,
    CSS,
    Language {
        id: "java",
        aliases: &[],
        extensions: &[".java"],
    },
    Language {
        id: "wren",
        aliases: &[],
        extensions: &[".wren"],
    },
    Language {
        id: "sql",
        aliases: &["postgres", "postgresql", "mysql"],
        extensions: &[".sql"],
    },
    Language {
        id: "lua",
        aliases: &["luau"],
        extensions: &[".lua", ".luau"],
    },
];

pub fn select(language: &str, languages: &[String]) -> Result<Vec<Language>, String> {
    let requested = if languages.is_empty() {
        vec![language.to_owned()]
    } else {
        languages.to_vec()
    };
    if requested.is_empty()
        || requested
            .iter()
            .any(|value| value.eq_ignore_ascii_case("auto"))
    {
        return Ok(LANGUAGES.to_vec());
    }

    let mut selected = Vec::new();
    for requested_name in requested {
        let normalized = requested_name.to_ascii_lowercase();
        if normalized == "frontend" || normalized == "web" {
            for definition in FRONTEND_LANGUAGES.iter().copied() {
                if !selected
                    .iter()
                    .any(|item: &Language| item.id == definition.id)
                {
                    selected.push(definition);
                }
            }
            continue;
        }
        let definition = LANGUAGES
            .iter()
            .copied()
            .find(|candidate| candidate.matches(&normalized))
            .ok_or_else(|| format!("Unknown Code Buster language: {requested_name}"))?;
        if !selected
            .iter()
            .any(|item: &Language| item.id == definition.id)
        {
            selected.push(definition);
        }
    }
    Ok(selected)
}

pub fn by_extension(selected: &[Language], extension: &str) -> Option<Language> {
    selected
        .iter()
        .copied()
        .find(|language| language.owns_extension(extension))
}

pub fn detect_versions(root: &Path) -> BTreeMap<String, String> {
    detect_versions_ordered(root).into_iter().collect()
}

pub fn detect_versions_ordered(root: &Path) -> Vec<(String, String)> {
    let mut manifests = Vec::new();
    collect_manifests(root, &mut manifests);
    manifests.sort();
    let mut versions = Vec::new();
    for path in manifests {
        let Ok(source) = fs::read(&path) else {
            continue;
        };
        let source = String::from_utf8_lossy(&source);
        match path.file_name().and_then(|name| name.to_str()) {
            Some("pubspec.yaml") => put(&mut versions, "dart", capture(&YAML_SDK_REGEX, &source)),
            Some("package.json") => package_json(&mut versions, &source),
            Some("go.mod") => put(&mut versions, "go", capture(&GO_REGEX, &source)),
            Some("Cargo.toml") => {
                put(&mut versions, "rust", capture(&RUST_REGEX, &source));
            }
            Some("pyproject.toml") => {
                put(&mut versions, "python", capture(&PYTHON_REGEX, &source));
            }
            Some("pom.xml") => put(&mut versions, "java", capture(&MAVEN_REGEX, &source)),
            Some("gradle.properties") => {
                put(&mut versions, "java", capture(&GRADLE_REGEX, &source));
            }
            _ => {}
        }
    }
    versions
}

fn collect_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if [
                ".git",
                ".dart_tool",
                "node_modules",
                "build",
                "dist",
                "target",
            ]
            .contains(&name.as_ref())
            {
                continue;
            }
            collect_manifests(&path, manifests);
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    [
                        "pubspec.yaml",
                        "package.json",
                        "go.mod",
                        "Cargo.toml",
                        "pyproject.toml",
                        "pom.xml",
                        "gradle.properties",
                    ]
                    .contains(&name)
                })
        {
            manifests.push(path);
        }
    }
}

fn package_json(versions: &mut Vec<(String, String)>, source: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(source) else {
        return;
    };
    put(
        versions,
        "node",
        value
            .get("engines")
            .and_then(|engines| engines.get("node"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    );
    for section in ["dependencies", "devDependencies"] {
        put(
            versions,
            "typescript",
            value
                .get(section)
                .and_then(|dependencies| dependencies.get("typescript"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        );
    }
}

fn capture(regex: &Regex, source: &str) -> Option<String> {
    regex
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn put(versions: &mut Vec<(String, String)>, language: &str, version: Option<String>) {
    if let Some(version) = version
        && !versions.iter().any(|(existing, _)| existing == language)
    {
        versions.push((language.to_owned(), version));
    }
}

static YAML_SDK_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s{2}sdk:\s*["']?([^"'\n]+)"#).unwrap());
static GO_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*go\s+(\S+)").unwrap());
static RUST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*rust-version\s*=\s*["']([^"']+)"#).unwrap());
static PYTHON_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"requires-python\s*=\s*["']([^"']+)"#).unwrap());
static MAVEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<maven\.compiler\.(?:release|source)>\s*([^<]+)").unwrap());
static GRADLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*(?:javaVersion|java_version)\s*=\s*(\S+)").unwrap());
