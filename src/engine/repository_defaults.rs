use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone, Debug)]
pub struct RepositoryDefaults {
    pub profiles: Vec<String>,
    pub frameworks: BTreeSet<String>,
    pub ignores: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RepositoryMetadataFile {
    pub relative: String,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct RepositoryDirectoryEntry {
    pub path: PathBuf,
    pub name: String,
    pub is_directory: bool,
}

pub type RepositoryDirectoryCache = HashMap<PathBuf, Vec<RepositoryDirectoryEntry>>;
#[derive(Clone, Debug)]
pub struct RepositoryInspection {
    pub defaults: RepositoryDefaults,
    pub metadata_files: Vec<RepositoryMetadataFile>,
    pub directories: RepositoryDirectoryCache,
}

impl RepositoryDefaults {
    pub fn inspect(
        root: &Path,
        include_tests: bool,
        include_examples: bool,
        include_vendored: bool,
    ) -> RepositoryInspection {
        let (profiles, metadata_files, directories) = inspect_repository(root);
        let frameworks = infer_frameworks(&profiles);
        let ignores = infer_ignores(&profiles, include_tests, include_examples, include_vendored);
        RepositoryInspection {
            defaults: Self {
                profiles: profiles.into_iter().collect(),
                frameworks,
                ignores,
            },
            metadata_files,
            directories,
        }
    }
}

fn inspect_repository(
    root: &Path,
) -> (
    BTreeSet<String>,
    Vec<RepositoryMetadataFile>,
    RepositoryDirectoryCache,
) {
    let mut profiles = BTreeSet::new();
    let mut metadata_files = Vec::new();
    let mut directories = HashMap::new();
    collect_repository_metadata(
        root,
        root,
        &mut profiles,
        &mut metadata_files,
        &mut directories,
    );
    if root.join("bin/flutter").is_file() && root.join("packages/flutter/pubspec.yaml").is_file() {
        profiles.insert("flutter-sdk".to_owned());
    }
    if root.join("configure.ac").is_file()
        && root.join("src/backend").is_dir()
        && root.join("contrib").is_dir()
    {
        profiles.insert("postgresql".to_owned());
    }
    metadata_files.sort_by(|left, right| left.relative.cmp(&right.relative));
    (profiles, metadata_files, directories)
}

fn infer_frameworks(profiles: &BTreeSet<String>) -> BTreeSet<String> {
    ["flutter", "react", "fastapi", "svelte", "pixijs"]
        .into_iter()
        .filter(|framework| match *framework {
            "flutter" => profiles.contains("flutter") || profiles.contains("flutter-sdk"),
            value => profiles.contains(value),
        })
        .map(str::to_owned)
        .collect()
}

fn infer_ignores(
    profiles: &BTreeSet<String>,
    include_tests: bool,
    include_examples: bool,
    include_vendored: bool,
) -> Vec<String> {
    let mut ignores = Vec::new();
    if !include_tests {
        ignores.extend(TEST_IGNORES.iter().map(|value| (*value).to_owned()));
    }
    if !include_examples {
        ignores.extend(EXAMPLE_IGNORES.iter().map(|value| (*value).to_owned()));
    }
    if !include_vendored {
        ignores.extend(VENDOR_IGNORES.iter().map(|value| (*value).to_owned()));
    }
    ignores.extend(DEFAULT_IGNORES.iter().map(|value| (*value).to_owned()));
    add_profile_ignores(profiles, include_tests, include_examples, &mut ignores);
    ignores
}

fn add_profile_ignores(
    profiles: &BTreeSet<String>,
    include_tests: bool,
    include_examples: bool,
    ignores: &mut Vec<String>,
) {
    add_flutter_ignores(profiles, include_tests, include_examples, ignores);
    add_test_profile_ignores(profiles, include_tests, ignores);
}

fn add_flutter_ignores(
    profiles: &BTreeSet<String>,
    include_tests: bool,
    include_examples: bool,
    ignores: &mut Vec<String>,
) {
    if profiles.contains("flutter") && !include_tests {
        ignores.push("**/integration_test/**".to_owned());
    }
    if !profiles.contains("flutter-sdk") {
        return;
    }
    if !include_tests {
        ignores.extend(
            [
                "dev/a11y_assessments/**",
                "dev/devicelab/**",
                "dev/integration_tests/**",
                "dev/manual_tests/**",
                "engine/src/flutter/testing/**",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    if !include_examples {
        ignores.push("dev/benchmarks/**".to_owned());
    }
}

fn add_test_profile_ignores(
    profiles: &BTreeSet<String>,
    include_tests: bool,
    ignores: &mut Vec<String>,
) {
    if include_tests {
        return;
    }
    for (profile, pattern) in [
        ("react", "**/__fixtures__/**"),
        ("dotnet", "**/TestResults/**"),
        ("postgresql", "contrib/*/sql/**"),
    ] {
        if profiles.contains(profile) {
            ignores.push(pattern.to_owned());
        }
    }
}

enum ProfileSource<'source> {
    Pubspec(&'source str),
    Package(&'source str),
    Python(&'source str),
    DotNet,
}

fn collect_repository_metadata(
    root: &Path,
    directory: &Path,
    profiles: &mut BTreeSet<String>,
    metadata_files: &mut Vec<RepositoryMetadataFile>,
    directories: &mut RepositoryDirectoryCache,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut entries = entries
        .flatten()
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
                return None;
            }
            Some(RepositoryDirectoryEntry {
                path: entry.path(),
                name: entry.file_name().to_string_lossy().into_owned(),
                is_directory: file_type.is_dir(),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    for entry in &entries {
        let Ok(relative) = entry.path.strip_prefix(root) else {
            continue;
        };
        if entry.is_directory {
            if !metadata_directory_excluded(relative) {
                collect_repository_metadata(
                    root,
                    &entry.path,
                    profiles,
                    metadata_files,
                    directories,
                );
            }
            continue;
        }
        if !is_repository_metadata_file(relative) {
            continue;
        }
        let source = read_manifest(&entry.path);
        if !manifest_excluded(relative)
            && let Some(profile_source) = profile_source(&entry.path, &source)
        {
            apply_profile_source(profile_source, profiles);
        }
        metadata_files.push(RepositoryMetadataFile {
            relative: relative.to_string_lossy().replace('\\', "/"),
            source,
        });
    }
    directories.insert(directory.to_owned(), entries);
}

fn profile_source<'source>(path: &Path, source: &'source str) -> Option<ProfileSource<'source>> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match name.as_str() {
        "pubspec.yaml" => Some(ProfileSource::Pubspec(source)),
        "package.json" => Some(ProfileSource::Package(source)),
        "requirements.txt" | "pyproject.toml" | "poetry.lock" | "pdm.lock" => {
            Some(ProfileSource::Python(source))
        }
        name if name.ends_with(".sln") || name.ends_with(".slnx") || name.ends_with(".csproj") => {
            Some(ProfileSource::DotNet)
        }
        _ => None,
    }
}

fn apply_profile_source(source: ProfileSource, profiles: &mut BTreeSet<String>) {
    match source {
        ProfileSource::Pubspec(source) => {
            let profile = if source.contains("flutter:") {
                "flutter"
            } else {
                "dart"
            };
            profiles.insert(profile.to_owned());
        }
        ProfileSource::Package(source) => apply_package_profiles(source, profiles),
        ProfileSource::Python(source) => {
            if FASTAPI.is_match(source) {
                profiles.insert("fastapi".to_owned());
            }
        }
        ProfileSource::DotNet => {
            profiles.insert("dotnet".to_owned());
        }
    }
}

fn apply_package_profiles(source: &str, profiles: &mut BTreeSet<String>) {
    let mut detected = false;
    for (pattern, profile) in [
        (&*REACT, "react"),
        (&*SVELTE, "svelte"),
        (&*PIXIJS, "pixijs"),
    ] {
        if pattern.is_match(source) {
            profiles.insert(profile.to_owned());
            detected = true;
        }
    }
    if !detected {
        profiles.insert("javascript/node".to_owned());
    }
}

fn metadata_directory_excluded(relative: &Path) -> bool {
    relative.file_name().is_some_and(|name| {
        [
            ".git",
            ".dart_tool",
            "node_modules",
            "build",
            "dist",
            "target",
        ]
        .iter()
        .any(|excluded| name == *excluded)
    })
}

fn is_repository_metadata_file(relative: &Path) -> bool {
    let name = relative
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    [
        "analysis_options.yaml",
        ".pre-commit-config.yaml",
        ".pre-commit-config.yml",
        "cargo.lock",
        "cargo.toml",
        "go.mod",
        "gradle.properties",
        "l10n.yaml",
        "package.json",
        "pdm.lock",
        "poetry.lock",
        "pom.xml",
        "pubspec.yaml",
        "pyproject.toml",
        "requirements.txt",
        "makefile",
    ]
    .contains(&lower.as_str())
        || lower.ends_with(".sln")
        || lower.ends_with(".slnx")
        || lower.ends_with(".csproj")
        || is_ci_metadata_path(relative)
}

fn is_ci_metadata_path(relative: &Path) -> bool {
    let file_name = relative.file_name().and_then(|name| name.to_str());
    let root_ci = relative.components().count() == 1
        && file_name.is_some_and(|name| {
            matches!(
                name,
                ".gitlab-ci.yml" | "azure-pipelines.yml" | "Jenkinsfile"
            )
        });
    let github_workflow = relative.parent() == Some(Path::new(".github/workflows"))
        && relative
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "yml" | "yaml"));
    root_ci || github_workflow
}

fn read_manifest(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn manifest_excluded(relative: &Path) -> bool {
    relative.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|name| {
            [
                ".git",
                "node_modules",
                "build",
                "dist",
                "obj",
                "vendor",
                "third_party",
                ".dart_tool",
            ]
            .contains(&name.to_ascii_lowercase().as_str())
        })
    })
}

static REACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[\"'](?:react|react-dom)[\"']\s*:"#).expect("React regex must compile")
});
static SVELTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[\"'](?:svelte|@sveltejs/kit)[\"']\s*:"#).expect("Svelte regex must compile")
});
static PIXIJS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[\"'](?:pixi\.js|@pixi/[^\"']+)[\"']\s*:"#).expect("PixiJS regex must compile")
});
static FASTAPI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(^|[\s\"'=])fastapi(?:[\s\"'<>=~^]|$)"#).expect("FastAPI regex must compile")
});

const DEFAULT_IGNORES: &[&str] = &[
    "**/.dart_tool/**",
    "**/*.generated.*",
    "**/*.gen.go",
    "**/*.pb.go",
    "**/*.pb.cc",
    "**/*.pb.h",
    "**/*.backup.js",
    "**/*.backup.jsx",
    "**/*.backup.mjs",
    "**/*.backup.cjs",
    "**/*.backup.ts",
    "**/*.backup.tsx",
    "**/*.backup.mts",
    "**/*.backup.cts",
    "**/migrations/**/definition.sql",
];

const TEST_IGNORES: &[&str] = &[
    "**/test/**",
    "**/*_test/**",
    "**/tests/**",
    "**/test_suite/**",
    "**/testenv/**",
    "**/testutil.*",
    "**/test_util.*",
    "**/testhelper.*",
    "**/test_helper.*",
    "**/testhelpers.*",
    "**/test_helpers.*",
    "**/test.ts",
    "**/test.tsx",
    "**/test.js",
    "**/test.jsx",
    "**/integration_tests/**",
    "**/test_integration/**",
    "**/*_integration_test_support/**",
    "**/test_fixes/**",
    "**/test_profile/**",
    "**/test_release/**",
    "**/automated_tests/**",
    "**/testing/**",
    "**/manual_tests/**",
    "**/*Tests/**",
    "**/*.Tests*/**",
    "**/*.Test/**",
    "**/*.UnitTests/**",
    "**/*.IntegrationTests/**",
    "**/testcase/**",
    "**/testcases/**",
    "**/__testfixtures__/**",
    "**/__tests__/**",
    "**/fixture/**",
    "**/fixtures/**",
    "**/testassets/**",
    "**/TestAssets/**",
    "**/test_assets/**",
    "**/src/*Test/**",
    "**/src/*test/**",
    "**/testdata/**",
    "**/src/it/**",
    "**/src/testFixtures/**",
    "**/__snapshots__/**",
    "**/*.snap",
    "**/*_test.go",
    "**/*_test.py",
    "**/*_test.rs",
    "**/*_test.cc",
    "**/*_test.cpp",
    "**/*_unittest.cc",
    "**/*_unittests.cc",
    "**/*_unittest.cpp",
    "**/*_unittests.cpp",
    "**/*_spec.rb",
    "**/*Test.java",
    "**/*_test.dart",
    "**/*Tests.java",
    "**/*.test.js",
    "**/*.test.jsx",
    "**/*.test.mjs",
    "**/*.test.cjs",
    "**/*.test.ts",
    "**/*.test.tsx",
    "**/*.test.mts",
    "**/*.test.cts",
    "**/*.spec.js",
    "**/*.spec.jsx",
    "**/*.spec.mjs",
    "**/*.spec.cjs",
    "**/*.spec.ts",
    "**/*.spec.tsx",
    "**/*.spec.mts",
    "**/*.spec.cts",
];

const EXAMPLE_IGNORES: &[&str] = &[
    "**/example/**",
    "**/examples/**",
    "**/docs_src/**",
    "**/evals/**",
    "**/example_*/**",
    "**/*_example/**",
    "**/*-example/**",
    "**/example-*/**",
    "**/*-examples/**",
    "**/sample/**",
    "**/samples/**",
    "**/Samples/**",
    "**/demo/**",
    "**/demos/**",
    "**/Demo/**",
    "**/Demos/**",
    "**/benches/**",
    "**/bench/**",
    "**/Bench/**",
    "**/benchmark/**",
    "**/Benchmark/**",
    "**/benchmarks/**",
    "**/Benchmarks/**",
    "**/*.Benchmark/**",
    "**/*.Benchmarks/**",
    "**/*-bench/**",
    "**/bench-*/**",
    "**/*-benchmark/**",
    "**/benchmark-*/**",
    "**/playground/**",
    "**/playgrounds/**",
    "**/benchmark.*",
    "**/bench.*",
    "**/storybook/**",
    "templates/**",
];

const VENDOR_IGNORES: &[&str] = &[
    "**/vendor/**",
    "**/vendored/**",
    "**/third_party/**",
    "**/compiled/**",
    "**/cargokit/**",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_nested_metadata_without_generated_dependency_directories() {
        let root = tempfile::tempdir().expect("temporary repository must be created");
        let member = root.path().join("member");
        let dependency = root.path().join("node_modules/dependency");
        fs::create_dir_all(&member).unwrap();
        fs::create_dir_all(&dependency).unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{"dependencies":{"react":"19.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nrust-version = \"1.85\"\n",
        )
        .unwrap();
        fs::write(root.path().join("Makefile"), "lint:\n\tcargo clippy\n").unwrap();
        fs::write(root.path().join(".pre-commit-config.yaml"), "repos: []\n").unwrap();
        fs::write(
            dependency.join("package.json"),
            r#"{"dependencies":{"svelte":"5.0.0"}}"#,
        )
        .unwrap();

        let inspection = RepositoryDefaults::inspect(root.path(), true, true, true);

        assert!(inspection.defaults.frameworks.contains("react"));
        assert!(!inspection.defaults.frameworks.contains("svelte"));
        assert_eq!(
            inspection
                .metadata_files
                .iter()
                .map(|file| file.relative.as_str())
                .collect::<Vec<_>>(),
            [
                ".pre-commit-config.yaml",
                "Makefile",
                "member/Cargo.toml",
                "package.json"
            ]
        );
        assert_eq!(
            crate::languages::detect_versions(&inspection.metadata_files).get("rust"),
            Some(&"1.85".to_owned())
        );
    }
}
