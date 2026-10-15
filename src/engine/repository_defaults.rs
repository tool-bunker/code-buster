use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone, Debug)]
pub struct RepositoryDefaults {
    pub profiles: Vec<String>,
    pub frameworks: BTreeSet<String>,
    pub ignores: Vec<String>,
}

impl RepositoryDefaults {
    pub fn infer(
        root: &Path,
        include_tests: bool,
        include_examples: bool,
        include_vendored: bool,
    ) -> Self {
        let profiles = infer_profiles(root);
        let frameworks = infer_frameworks(&profiles);
        let ignores = infer_ignores(&profiles, include_tests, include_examples, include_vendored);
        Self {
            profiles: profiles.into_iter().collect(),
            frameworks,
            ignores,
        }
    }
}

fn infer_profiles(root: &Path) -> BTreeSet<String> {
    let mut profiles = BTreeSet::new();
    collect_profiles(root, root, &mut profiles);
    if root.join("bin/flutter").is_file() && root.join("packages/flutter/pubspec.yaml").is_file() {
        profiles.insert("flutter-sdk".to_owned());
    }
    if root.join("configure.ac").is_file()
        && root.join("src/backend").is_dir()
        && root.join("contrib").is_dir()
    {
        profiles.insert("postgresql".to_owned());
    }
    profiles
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

enum ProfileSource {
    Pubspec(String),
    Package(String),
    Python(String),
    DotNet,
}

fn collect_profiles(root: &Path, directory: &Path, profiles: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        if manifest_excluded(relative) {
            continue;
        }
        if file_type.is_dir() {
            collect_profiles(root, &path, profiles);
        } else if let Some(source) = profile_source(&path) {
            apply_profile_source(source, profiles);
        }
    }
}

fn profile_source(path: &Path) -> Option<ProfileSource> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match name.as_str() {
        "pubspec.yaml" => Some(ProfileSource::Pubspec(read_manifest(path))),
        "package.json" => Some(ProfileSource::Package(read_manifest(path))),
        "requirements.txt" | "pyproject.toml" | "poetry.lock" | "pdm.lock" => {
            Some(ProfileSource::Python(read_manifest(path)))
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
        ProfileSource::Package(source) => apply_package_profiles(&source, profiles),
        ProfileSource::Python(source) => {
            if FASTAPI.is_match(&source) {
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

fn read_manifest(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
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
