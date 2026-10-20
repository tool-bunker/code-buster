use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::cli::PreviewOptions;
use crate::config::{Config, absolute_root};
use crate::languages::{self, Language};
use crate::repository_defaults::{
    RepositoryDefaults, RepositoryDirectoryCache, RepositoryDirectoryEntry, RepositoryInspection,
    RepositoryMetadataFile,
};

#[derive(Clone, Debug, Serialize)]
pub struct SourceFile {
    pub path: String,
    pub language: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneratedProvenance {
    pub path: String,
    pub reason: String,
    pub source: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessingDiagnostic {
    pub code: &'static str,
    pub severity: &'static str,
    pub stage: &'static str,
    pub message: String,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangedLineRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub struct RulePackTiming {
    pub id: String,
    pub family: String,
    pub duration_microseconds: u128,
}

#[derive(Debug, Default)]
pub struct AnalysisProfile {
    pub rule_packs: Vec<RulePackTiming>,
    pub shared_durations_microseconds: BTreeMap<String, u128>,
    pub rule_durations_microseconds: BTreeMap<String, u128>,
}

#[derive(Debug)]
pub struct PreparedPreview {
    pub root: String,
    pub config: Config,
    pub files: Vec<SourceFile>,
    pub excluded_source_files: Vec<SourceFile>,
    pub sources: BTreeMap<String, String>,
    pub coverage: BTreeMap<String, usize>,
    pub language_versions: BTreeMap<String, String>,
    pub generated_provenance: Vec<GeneratedProvenance>,
    pub changed_line_ranges: BTreeMap<String, Vec<ChangedLineRange>>,
    pub changed_paths: BTreeSet<String>,
    pub diagnostics: Vec<ProcessingDiagnostic>,
    pub graph_cache_hit: bool,
    pub findings_cache_hit: bool,
    pub duration_milliseconds: u128,
    pub stage_durations_milliseconds: BTreeMap<String, u128>,
    pub rule_family_durations_milliseconds: BTreeMap<String, u128>,
    pub analysis_profile: AnalysisProfile,
    pub(crate) metadata_files: Vec<RepositoryMetadataFile>,
}

// code-buster-ignore complex-function: one ordered discovery pipeline owns configuration and coverage state.
pub fn prepare(options: &PreviewOptions) -> Result<PreparedPreview, String> {
    let root = absolute_root(&options.root)?;
    let mut config = Config::load(root.clone(), options)?;
    let RepositoryInspection {
        defaults,
        metadata_files,
        directories,
    } = RepositoryDefaults::inspect(
        &root,
        config.include_all || config.include_tests,
        config.include_all || config.include_examples,
        config.include_all || config.include_vendored,
    );
    config.frameworks = defaults.frameworks;
    if !config.include_all {
        config.ignore_patterns.extend(defaults.ignores);
    }
    if !config.include_all && !config.include_tests {
        config
            .ignore_patterns
            .extend(config.classification_test.iter().cloned());
    }
    config
        .ignore_patterns
        .extend(config.classification_generated.iter().cloned());
    let auto_requested = (config.languages.is_empty() && config.language == "auto")
        || config
            .languages
            .iter()
            .any(|language| language.eq_ignore_ascii_case("auto"));
    let selected = languages::select(&config.language, &config.languages)?;
    let policy = RepositoryPolicy::infer(&root);
    let changed = config
        .changed_base
        .as_deref()
        .map_or_else(BTreeSet::new, |base| changed_files(&root, base));
    let mut discovery = Discovery::new(config, selected, policy, changed, directories)?;
    discovery.walk_root()?;
    discovery
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    discovery
        .excluded_source_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    discovery
        .generated_provenance
        .sort_by(|left, right| left.path.cmp(&right.path));
    if auto_requested {
        let detected = detected_languages(&root, &discovery.files);
        if let Some(language) = detected.first() {
            discovery.config.language = language.clone();
            discovery.config.languages = detected;
        }
    }

    let sources = discovery.sources;
    let diagnostics = discovery.diagnostics;
    let language_versions = languages::detect_versions(&metadata_files);
    let changed_line_ranges = changed_line_ranges(&root, discovery.config.changed_base.as_deref());
    let root = root
        .to_str()
        .ok_or_else(|| "analysis root must be valid UTF-8".to_owned())?
        .to_owned();
    Ok(PreparedPreview {
        root,
        config: discovery.config,
        files: discovery.files,
        excluded_source_files: discovery.excluded_source_files,
        sources,
        coverage: discovery.coverage,
        language_versions,
        generated_provenance: discovery.generated_provenance,
        changed_line_ranges,
        changed_paths: discovery.changed,
        diagnostics,
        graph_cache_hit: false,
        findings_cache_hit: false,
        duration_milliseconds: 0,
        stage_durations_milliseconds: BTreeMap::new(),
        rule_family_durations_milliseconds: BTreeMap::new(),
        analysis_profile: AnalysisProfile::default(),
        metadata_files,
    })
}

fn detected_languages(root: &Path, files: &[SourceFile]) -> Vec<String> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for file in files {
        *counts.entry(file.language.as_str()).or_default() += 1;
    }
    let manifests = manifest_languages(root);
    let one_language_only = counts.len() == 1;
    languages::LANGUAGES
        .iter()
        .filter(|language| {
            counts.get(language.id).copied().unwrap_or_default() >= 2
                || manifests.contains(language.id)
                || (one_language_only && counts.get(language.id).copied().unwrap_or_default() > 0)
        })
        .map(|language| language.id.to_owned())
        .collect()
}

fn manifest_languages(root: &Path) -> BTreeSet<&'static str> {
    let mut manifests = BTreeSet::new();
    for (manifest, language) in [
        ("pubspec.yaml", "dart"),
        ("Cargo.toml", "rust"),
        ("package.json", "javascript"),
        ("deno.json", "javascript"),
        ("deno.jsonc", "javascript"),
    ] {
        if root.join(manifest).is_file() {
            manifests.insert(language);
        }
    }
    if let Ok(entries) = fs::read_dir(root) {
        for name in entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
            .map(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase())
        {
            if name.ends_with(".csproj") {
                manifests.insert("csharp");
            }
            if name.ends_with(".nimble") {
                manifests.insert("nim");
            }
        }
    }
    manifests
}

enum EntryKind {
    Directory,
    File,
    Other,
}

struct DiscoveryEntry {
    kind: EntryKind,
    path: std::path::PathBuf,
    relative: String,
    name: String,
}

enum DirectoryAction {
    Skip,
    Count(&'static str),
    Traverse,
}

struct Discovery {
    config: Config,
    selected: Vec<Language>,
    policy: RepositoryPolicy,
    changed: BTreeSet<String>,
    directories: RepositoryDirectoryCache,
    ignores: Vec<PathPattern>,
    includes: Vec<PathPattern>,
    excludes: Vec<PathPattern>,
    production: Vec<PathPattern>,
    classified_test: Vec<PathPattern>,
    classified_generated: Vec<PathPattern>,
    files: Vec<SourceFile>,
    excluded_source_files: Vec<SourceFile>,
    sources: BTreeMap<String, String>,
    coverage: BTreeMap<String, usize>,
    generated_provenance: Vec<GeneratedProvenance>,
    diagnostics: Vec<ProcessingDiagnostic>,
}

impl Discovery {
    fn new(
        config: Config,
        selected: Vec<Language>,
        policy: RepositoryPolicy,
        changed: BTreeSet<String>,
        directories: RepositoryDirectoryCache,
    ) -> Result<Self, String> {
        Ok(Self {
            ignores: compile_patterns(&config.ignore_patterns)?,
            includes: compile_patterns(&config.includes)?,
            excludes: compile_patterns(&config.excludes)?,
            production: compile_patterns(&config.classification_production)?,
            classified_test: compile_patterns(&config.classification_test)?,
            classified_generated: compile_patterns(&config.classification_generated)?,
            config,
            selected,
            policy,
            changed,
            directories,
            files: Vec::new(),
            excluded_source_files: Vec::new(),
            sources: BTreeMap::new(),
            coverage: BTreeMap::new(),
            generated_provenance: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn walk_root(&mut self) -> Result<(), String> {
        let root = self.config.root.clone();
        let mut git_rules = Vec::new();
        self.scan_directory(&root, &mut git_rules)
    }

    fn scan_directory(
        &mut self,
        directory: &Path,
        git_rules: &mut Vec<GitIgnoreRule>,
    ) -> Result<(), String> {
        let inherited_rules = git_rules.len();
        let ignore_file = directory.join(".gitignore");
        if ignore_file.is_file() {
            self.read_gitignore(&ignore_file, git_rules)?;
        }

        let entries = self.directory_entries(directory)?;
        for entry in entries {
            self.process_entry(entry, git_rules)?;
        }
        git_rules.truncate(inherited_rules);
        Ok(())
    }

    fn directory_entries(&mut self, directory: &Path) -> Result<Vec<DiscoveryEntry>, String> {
        if let Some(entries) = self.directories.remove(directory) {
            return entries
                .into_iter()
                .map(|entry| self.cached_entry(entry))
                .collect();
        }

        let entries = fs::read_dir(directory)
            .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("failed to read {}: {error}", directory.display()))?;
        let mut entries = entries
            .into_iter()
            .map(|entry| (entry.path(), entry))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
            .into_iter()
            .filter_map(|(path, entry)| self.classify_entry(path, entry).transpose())
            .collect()
    }

    fn cached_entry(&self, entry: RepositoryDirectoryEntry) -> Result<DiscoveryEntry, String> {
        Ok(DiscoveryEntry {
            kind: if entry.is_directory {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            relative: relative_path(&self.config.root, &entry.path)?,
            path: entry.path,
            name: entry.name,
        })
    }

    fn classify_entry(
        &self,
        path: std::path::PathBuf,
        entry: fs::DirEntry,
    ) -> Result<Option<DiscoveryEntry>, String> {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Ok(None);
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = relative_path(&self.config.root, &path)?;
        let kind = if file_type.is_dir() {
            EntryKind::Directory
        } else if file_type.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        Ok(Some(DiscoveryEntry {
            kind,
            path,
            relative,
            name,
        }))
    }

    fn process_entry(
        &mut self,
        entry: DiscoveryEntry,
        git_rules: &mut Vec<GitIgnoreRule>,
    ) -> Result<(), String> {
        match entry.kind {
            EntryKind::Directory => {
                self.process_directory(&entry.path, &entry.name, &entry.relative, git_rules)
            }
            EntryKind::File => self.consider_file(&entry.path, &entry.relative, git_rules),
            EntryKind::Other => Ok(()),
        }
    }

    fn process_directory(
        &mut self,
        path: &Path,
        name: &str,
        relative: &str,
        git_rules: &mut Vec<GitIgnoreRule>,
    ) -> Result<(), String> {
        match self.directory_action(name, relative, git_rules) {
            DirectoryAction::Skip => Ok(()),
            DirectoryAction::Count(reason) => self.count_excluded_directory(path, reason),
            DirectoryAction::Traverse => self.scan_directory(path, git_rules),
        }
    }

    fn directory_action(
        &self,
        name: &str,
        relative: &str,
        git_rules: &[GitIgnoreRule],
    ) -> DirectoryAction {
        if is_default_ignored_directory(name, relative) || name.starts_with('.') {
            return DirectoryAction::Skip;
        }
        if name.to_ascii_lowercase().ends_with(".framework") {
            return DirectoryAction::Count("generated");
        }
        if self.production.is_empty()
            && matches_prefixes(&relative_with_slash(relative), &self.ignores)
        {
            let role = classify_path(relative, &self.policy);
            return DirectoryAction::Count(coverage_reason(role));
        }
        if is_git_ignored(&relative_with_slash(relative), true, git_rules) {
            return DirectoryAction::Count("policy_ignored");
        }
        DirectoryAction::Traverse
    }

    fn consider_file(
        &mut self,
        path: &Path,
        relative: &str,
        git_rules: &[GitIgnoreRule],
    ) -> Result<(), String> {
        let forced_production = matches_any(relative, &self.production);
        let forced_generated = matches_any(relative, &self.classified_generated);
        let extension = extension(path);
        let Some(language) = self.language_for_path(path, extension) else {
            self.record_unrecognized_extension(extension);
            return Ok(());
        };

        let exclusion_reason = (!forced_production)
            .then(|| self.exclusion_reason(relative, git_rules))
            .flatten();
        let unchanged = self.config.changed_base.is_some() && !self.changed.contains(relative);
        if forced_generated || exclusion_reason.is_some() || unchanged {
            let generated = GeneratedEvidence::detect(path, relative, extension)?;
            if self.should_exclude_generated(
                relative,
                git_rules,
                forced_production,
                forced_generated,
                generated,
            ) {
                self.record_generated(relative, forced_generated, generated);
            } else if let Some(reason) = exclusion_reason {
                self.record(reason);
                self.record_excluded_source(relative, language.id, reason);
            } else {
                self.record("unchanged");
            }
            return Ok(());
        }

        let bytes = fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let generated = GeneratedEvidence::from_bytes(relative, extension, &bytes);
        if self.should_exclude_generated(relative, git_rules, forced_production, false, generated) {
            self.record_generated(relative, false, generated);
            return Ok(());
        }
        let source = decode_source(bytes, relative, &mut self.coverage, &mut self.diagnostics);
        self.record("selected");
        self.files.push(SourceFile {
            path: relative.to_owned(),
            language: language.id.to_owned(),
        });
        self.sources.insert(relative.to_owned(), source);
        Ok(())
    }

    fn language_for_path(&self, path: &Path, extension: &str) -> Option<Language> {
        let shebang_language = extension.is_empty().then(|| {
            self.selected
                .iter()
                .copied()
                .find(|language| language.id == "lua")
                .filter(|_| has_lua_shebang(path))
        });
        shebang_language
            .flatten()
            .or_else(|| languages::by_extension(&self.selected, extension))
    }

    fn record_unrecognized_extension(&mut self, extension: &str) {
        if looks_like_unsupported_source(extension) {
            self.record("unsupported");
        } else if looks_binary(extension) {
            self.record("binary");
        }
    }

    fn should_exclude_generated(
        &self,
        relative: &str,
        git_rules: &[GitIgnoreRule],
        forced_production: bool,
        forced_generated: bool,
        generated: GeneratedEvidence,
    ) -> bool {
        forced_generated
            || (!forced_production
                && generated.any()
                && !is_explicitly_git_included(relative, git_rules))
    }

    fn record_generated(
        &mut self,
        relative: &str,
        forced_generated: bool,
        generated: GeneratedEvidence,
    ) {
        self.record("generated");
        self.generated_provenance.push(GeneratedProvenance {
            path: relative.to_owned(),
            reason: generated.reason(forced_generated).to_owned(),
            source: if forced_generated {
                "code-buster.toml"
            } else {
                "built-in generated policy"
            }
            .to_owned(),
        });
    }

    fn exclusion_reason(
        &self,
        relative: &str,
        git_rules: &[GitIgnoreRule],
    ) -> Option<&'static str> {
        if is_git_ignored(relative, false, git_rules) {
            return Some("git_ignored");
        }
        let role = if matches_any(relative, &self.classified_test) {
            SourceRole::Test
        } else {
            classify_file_role(relative, &self.policy)
        };
        let ignored_by_role = excludes_source_role(
            role,
            self.config.include_all,
            self.config.include_tests,
            self.config.include_examples,
            self.config.include_vendored,
        );
        let ignored_by_policy = ignored_by_role
            || matches_prefixes(relative, &self.ignores)
            || matches_prefixes(relative, &self.excludes)
            || (!self.includes.is_empty() && !matches_prefixes(relative, &self.includes));
        ignored_by_policy.then(|| coverage_reason(role))
    }

    fn count_excluded_directory(&mut self, directory: &Path, reason: &str) -> Result<(), String> {
        let mut directories = vec![directory.to_owned()];
        while let Some(current) = directories.pop() {
            let entries = fs::read_dir(&current)
                .map_err(|error| format!("failed to read {}: {error}", current.display()))?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    format!("failed to read entry under {}: {error}", current.display())
                })?;
                self.count_excluded_entry(entry, reason, &mut directories)?;
            }
        }
        Ok(())
    }

    fn count_excluded_entry(
        &mut self,
        entry: fs::DirEntry,
        reason: &str,
        directories: &mut Vec<std::path::PathBuf>,
    ) -> Result<(), String> {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            return Ok(());
        }
        let path = entry.path();
        if file_type.is_dir() {
            directories.push(path);
            return Ok(());
        }
        if file_type.is_file()
            && let Some(language) = languages::by_extension(&self.selected, extension(&path))
        {
            self.record_excluded_file(&path, language.id, reason)?;
        }
        Ok(())
    }

    fn record_excluded_file(
        &mut self,
        path: &Path,
        language: &str,
        reason: &str,
    ) -> Result<(), String> {
        self.record(reason);
        let relative = relative_path(&self.config.root, path)?;
        self.record_excluded_source(&relative, language, reason);
        if reason == "generated" {
            self.generated_provenance.push(GeneratedProvenance {
                path: relative,
                reason: "inside generated output directory".to_owned(),
                source: "built-in generated policy".to_owned(),
            });
        }
        Ok(())
    }

    fn record_excluded_source(&mut self, path: &str, language: &str, reason: &str) {
        if matches!(reason, "test" | "example") {
            self.excluded_source_files.push(SourceFile {
                path: path.to_owned(),
                language: language.to_owned(),
            });
        }
    }

    fn read_gitignore(&self, file: &Path, rules: &mut Vec<GitIgnoreRule>) -> Result<(), String> {
        let source = fs::read_to_string(file)
            .map_err(|error| format!("failed to read {}: {error}", file.display()))?;
        let parent = file
            .parent()
            .ok_or_else(|| format!("gitignore path has no parent: {}", file.display()))?;
        let base = relative_path(&self.config.root, parent)?;
        for raw_line in source.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let negated = line.starts_with('!');
            let without_negation = line.strip_prefix('!').unwrap_or(line);
            let anchored = without_negation.starts_with('/');
            let directory_only = without_negation.ends_with('/');
            let pattern = without_negation.trim_matches('/').to_owned();
            rules.push(GitIgnoreRule {
                base: if base == "." {
                    String::new()
                } else {
                    base.clone()
                },
                matcher: compile_glob(&pattern)?,
                pattern,
                negated,
                directory_only,
                anchored,
            });
        }
        Ok(())
    }

    fn record(&mut self, reason: &str) {
        *self.coverage.entry(reason.to_owned()).or_default() += 1;
    }
}
fn classify_file_role(relative: &str, policy: &RepositoryPolicy) -> SourceRole {
    let role = classify_path(relative, policy);
    let normalized = normalize_path(relative);
    let segments = normalized.split('/').collect::<Vec<_>>();
    let name = segments.last().copied().unwrap_or_default();
    match role {
        SourceRole::Example if !is_example_path(&segments) => SourceRole::Production,
        SourceRole::Vendored
            if !VERSIONED_VENDOR_ASSET.is_match(name)
                && !["vendor", "vendored", "third_party", "compiled", "cargokit"]
                    .iter()
                    .any(|candidate| segments.contains(candidate)) =>
        {
            SourceRole::Production
        }
        SourceRole::Generated
            if !is_generated_file_name(name) && !is_generated_directory(&segments) =>
        {
            SourceRole::Production
        }
        _ => role,
    }
}

fn excludes_source_role(
    role: SourceRole,
    include_all: bool,
    include_tests: bool,
    include_examples: bool,
    include_vendored: bool,
) -> bool {
    match role {
        SourceRole::Test => !include_all && !include_tests,
        SourceRole::Example => !include_all && !include_examples,
        SourceRole::Vendored => !include_all && !include_vendored,
        SourceRole::Generated => true,
        SourceRole::Production => false,
    }
}

#[derive(Clone, Copy)]
struct GeneratedEvidence {
    by_name: bool,
    by_header: bool,
    by_minification: bool,
}

impl GeneratedEvidence {
    fn detect(path: &Path, relative: &str, extension: &str) -> Result<Self, String> {
        Ok(Self {
            by_name: is_generated_by_name(relative),
            by_header: has_generated_header(path)?,
            by_minification: is_minified_bundle(path, extension)?,
        })
    }

    fn from_bytes(relative: &str, extension: &str, bytes: &[u8]) -> Self {
        Self {
            by_name: is_generated_by_name(relative),
            by_header: has_generated_header_bytes(bytes),
            by_minification: is_minified_bundle_bytes(bytes, extension),
        }
    }

    fn any(self) -> bool {
        self.by_name || self.by_header || self.by_minification
    }

    fn reason(self, forced: bool) -> &'static str {
        if forced {
            "matched classification.generated override"
        } else if self.by_name {
            "matched generated filename convention"
        } else if self.by_header {
            "matched generated source header"
        } else {
            "matched minified bundle content"
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceRole {
    Production,
    Test,
    Example,
    Vendored,
    Generated,
}

pub struct TargetClassification {
    pub classification: &'static str,
    pub source: &'static str,
    pub matched: Option<String>,
}

pub fn classify_target(
    root: &Path,
    relative: &str,
    config: &Config,
) -> Result<TargetClassification, String> {
    let overrides = [
        ("production", &config.classification_production),
        ("test", &config.classification_test),
        ("generated", &config.classification_generated),
    ];
    for (classification, patterns) in overrides.into_iter().rev() {
        let compiled = compile_patterns(patterns)?;
        if let Some(pattern) = compiled
            .iter()
            .find(|pattern| pattern.matcher.is_match(relative))
        {
            return Ok(TargetClassification {
                classification,
                source: "code-buster.toml",
                matched: Some(pattern.normalized.clone()),
            });
        }
    }
    let classification = match classify_path(relative, &RepositoryPolicy::infer(root)) {
        SourceRole::Production => "production",
        SourceRole::Test => "test",
        SourceRole::Example => "example",
        SourceRole::Vendored => "vendored",
        SourceRole::Generated => "generated",
    };
    Ok(TargetClassification {
        classification,
        source: "built-in language/framework defaults",
        matched: None,
    })
}

fn coverage_reason(role: SourceRole) -> &'static str {
    match role {
        SourceRole::Test => "test",
        SourceRole::Example => "example",
        SourceRole::Vendored => "vendored",
        SourceRole::Generated => "generated",
        SourceRole::Production => "policy_ignored",
    }
}

#[derive(Default)]
struct RepositoryPolicy {
    postgresql: bool,
}

impl RepositoryPolicy {
    fn infer(root: &Path) -> Self {
        Self {
            postgresql: root.join("configure.ac").is_file()
                && root.join("src/backend").is_dir()
                && root.join("contrib").is_dir(),
        }
    }
}

fn classify_path(relative: &str, policy: &RepositoryPolicy) -> SourceRole {
    let normalized = normalize_classification_path(relative);
    let segments = normalized.split('/').collect::<Vec<_>>();
    let name = segments.last().copied().unwrap_or_default();

    if is_classified_test(&normalized, name, &segments, policy) {
        return SourceRole::Test;
    }
    if is_generated_file_name(name) {
        return SourceRole::Generated;
    }
    if VERSIONED_VENDOR_ASSET.is_match(name) {
        return SourceRole::Vendored;
    }
    if is_example_path(&segments) {
        return SourceRole::Example;
    }
    if ["vendor", "vendored", "third_party", "compiled", "cargokit"]
        .iter()
        .any(|candidate| segments.contains(candidate))
    {
        return SourceRole::Vendored;
    }
    if is_generated_directory(&segments) {
        return SourceRole::Generated;
    }
    SourceRole::Production
}

pub(crate) fn is_builtin_production_path(relative: &str) -> bool {
    classify_path(relative, &RepositoryPolicy::default()) == SourceRole::Production
}

fn is_test_file_name(name: &str) -> bool {
    TEST_FILE_REGEX.is_match(name)
}

fn is_generated_file_name(name: &str) -> bool {
    name.contains(".generated.")
        || name.contains("_generated.")
        || BACKUP_FILE_REGEX.is_match(name)
        || [".gen.go", ".pb.go", ".pb.cc", ".pb.h"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

const TEST_PATH_SEGMENTS: &[&str] = &[
    "test",
    "tests",
    "tests_common",
    "__tests__",
    "test_suite",
    "testassets",
    "testenv",
    "test_assets",
    "integration_test",
    "integration_tests",
    "test_integration",
    "test_fixes",
    "testcase",
    "testcases",
    "__testfixtures__",
    "test_profile",
    "test_release",
    "automated_tests",
    "testing",
    "manual_tests",
    "testresults",
    "__fixtures__",
    ".fixtures",
    "fixture",
    "fixtures",
];

const TEST_PATH_SUFFIXES: &[&str] = &[
    ".test",
    ".tests",
    ".unittest",
    ".unittests",
    ".integrationtest",
    ".integrationtests",
];

const UNIT_TEST_PATH_SEGMENTS: &[&str] = &["test-unit", "tests-unit", "unit-tests"];

const FUZZ_PATH_SEGMENTS: &[&str] = &["fuzz", "fuzzing", "fuzz_targets"];

const TEST_SEGMENT_PREFIXES: &[&str] = &["test-", "tests-", "testing-", "fixture-", "fixtures-"];
const TEST_SEGMENT_SUFFIXES: &[&str] = &[
    "-test",
    "-tests",
    "-testing",
    "-fixture",
    "-fixtures",
    "-e2e",
];
const EXAMPLE_SEGMENT_PREFIXES: &[&str] = &["example_", "example-", "bench-", "benchmark-"];
const EXAMPLE_SEGMENT_SUFFIXES: &[&str] = &[
    "_example",
    "-example",
    "_examples",
    "-examples",
    "-bench",
    "-benchmark",
    ".benchmark",
    ".benchmarks",
    "-docs",
];

fn is_classified_test(
    normalized: &str,
    name: &str,
    segments: &[&str],
    policy: &RepositoryPolicy,
) -> bool {
    segments
        .iter()
        .any(|segment| segment.ends_with("_test") || segment.ends_with("_tests"))
        || is_test_file_name(name)
        || is_test_path(normalized, name, segments)
        || policy.postgresql && segments.first() == Some(&"contrib") && segments.contains(&"sql")
}

fn is_test_path(normalized: &str, name: &str, segments: &[&str]) -> bool {
    TEST_HELPER_REGEX.is_match(name)
        || is_source_test_path(normalized)
        || TEST_PATH_SEGMENTS
            .iter()
            .any(|candidate| segments.contains(candidate))
        || FUZZ_PATH_SEGMENTS
            .iter()
            .any(|candidate| segments.contains(candidate))
        || segments.iter().copied().any(is_test_path_segment)
}

fn is_source_test_path(normalized: &str) -> bool {
    SRC_TEST_REGEX.is_match(normalized)
        || is_nested_or_terminal_path(normalized, "/src/it/", "/src/it", "src/it")
        || is_nested_or_terminal_path(
            normalized,
            "/src/testfixtures/",
            "/src/testfixtures",
            "src/testfixtures",
        )
}

fn is_nested_or_terminal_path(
    normalized: &str,
    nested: &str,
    terminal: &str,
    entire: &str,
) -> bool {
    normalized.contains(nested) || normalized.ends_with(terminal) || normalized == entire
}

fn is_test_path_segment(segment: &str) -> bool {
    TEST_PATH_SUFFIXES
        .iter()
        .any(|suffix| segment.ends_with(suffix))
        || segment.contains(".tests.")
        || has_any_affix(segment, TEST_SEGMENT_PREFIXES, TEST_SEGMENT_SUFFIXES)
        || segment == "e2e"
        || UNIT_TEST_PATH_SEGMENTS.contains(&segment)
}

fn is_example_path(segments: &[&str]) -> bool {
    segments.first() == Some(&"templates")
        || [
            "example",
            "examples",
            "sample",
            "samples",
            "demo",
            "demos",
            "docs_src",
            "benches",
            "bench",
            "benchmark",
            "benchmarks",
            "jmh",
            "playground",
            "playgrounds",
            "storybook",
            "evals",
        ]
        .iter()
        .any(|candidate| segments.contains(candidate))
        || segments.iter().any(|segment| {
            !segment.contains('.')
                && has_any_affix(segment, EXAMPLE_SEGMENT_PREFIXES, EXAMPLE_SEGMENT_SUFFIXES)
        })
        || segments.last().is_some_and(|name| {
            let stem = name.split('.').next().unwrap_or(name);
            matches!(stem, "bench" | "benchmark")
                || name.ends_with("-example.html")
                || name.ends_with("_example.html")
                || name.ends_with("-example.htm")
                || name.ends_with("_example.htm")
        })
}

fn has_any_affix(value: &str, prefixes: &[&str], suffixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| value.starts_with(prefix))
        || suffixes.iter().any(|suffix| value.ends_with(suffix))
}

fn is_generated_directory(segments: &[&str]) -> bool {
    let build_index = segments.iter().position(|segment| *segment == "build");
    let source_build = build_index.is_some_and(|index| {
        index > 0 && ["command", "commands", "cmd", "cmds"].contains(&segments[index - 1])
    });
    (!source_build && build_index.is_some())
        || ["dist", "obj", ".dart_tool"]
            .iter()
            .any(|candidate| segments.contains(candidate))
}

#[derive(Debug)]
struct PathPattern {
    normalized: String,
    wildcard: bool,
    matcher: Regex,
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<PathPattern>, String> {
    patterns
        .iter()
        .filter_map(|raw| {
            let normalized = raw.trim().replace('\\', "/").trim_matches('/').to_owned();
            (!normalized.is_empty()).then_some(normalized)
        })
        .map(|normalized| {
            Ok(PathPattern {
                wildcard: normalized.contains('*'),
                matcher: compile_glob(&normalized)?,
                normalized,
            })
        })
        .collect()
}

fn matches_any(relative: &str, patterns: &[PathPattern]) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern.matcher.is_match(relative))
}

fn matches_prefixes(relative: &str, patterns: &[PathPattern]) -> bool {
    let normalized = normalize_path(relative);
    patterns.iter().any(|pattern| {
        if pattern.wildcard {
            pattern.matcher.is_match(&normalized)
        } else {
            normalized.starts_with(&pattern.normalized)
                || normalized.contains(&format!("/{}", pattern.normalized))
        }
    })
}

fn compile_glob(pattern: &str) -> Result<Regex, String> {
    let mut expression = String::from("^");
    let characters = pattern.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '*' {
            if characters.get(index + 1) == Some(&'*') {
                if characters.get(index + 2) == Some(&'/') {
                    expression.push_str("(?:.*/)?");
                    index += 3;
                    continue;
                }
                expression.push_str(".*");
                index += 2;
                continue;
            }
            expression.push_str("[^/]*");
        } else {
            expression.push_str(&regex::escape(&characters[index].to_string()));
        }
        index += 1;
    }
    expression.push('$');
    Regex::new(&expression).map_err(|error| format!("invalid path pattern `{pattern}`: {error}"))
}

struct GitIgnoreRule {
    base: String,
    pattern: String,
    matcher: Regex,
    negated: bool,
    directory_only: bool,
    anchored: bool,
}

fn is_git_ignored(relative: &str, is_directory: bool, rules: &[GitIgnoreRule]) -> bool {
    let normalized = normalize_path(relative);
    let normalized = normalized.trim_end_matches('/');
    applicable_git_ignore_rules(normalized, rules).fold(false, |ignored, (rule, local)| {
        evaluate_git_ignore_rule(rule, local, is_directory).unwrap_or(ignored)
    })
}

fn applicable_git_ignore_rules<'path, 'rules>(
    relative: &'path str,
    rules: &'rules [GitIgnoreRule],
) -> impl Iterator<Item = (&'rules GitIgnoreRule, &'path str)> {
    rules.iter().filter_map(move |rule| {
        path_relative_to_gitignore(relative, &rule.base).map(|local| (rule, local))
    })
}

fn path_relative_to_gitignore<'a>(relative: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(relative);
    }
    if relative == base {
        return Some("");
    }
    relative.strip_prefix(base)?.strip_prefix('/')
}

fn evaluate_git_ignore_rule(rule: &GitIgnoreRule, local: &str, is_directory: bool) -> Option<bool> {
    git_ignore_rule_matches(rule, local, is_directory).then_some(!rule.negated)
}

fn git_ignore_rule_matches(rule: &GitIgnoreRule, local: &str, is_directory: bool) -> bool {
    let wildcard = rule.pattern.contains('*');
    let matches = git_ignore_pattern_matches(rule, local, wildcard)
        || (!rule.anchored
            && local
                .split('/')
                .any(|segment| git_ignore_pattern_matches(rule, segment, wildcard)));
    matches && (!rule.directory_only || is_directory || path_is_below_pattern(local, &rule.pattern))
}

fn git_ignore_pattern_matches(rule: &GitIgnoreRule, candidate: &str, wildcard: bool) -> bool {
    if wildcard {
        rule.matcher.is_match(candidate)
    } else {
        candidate == rule.pattern || path_is_below_pattern(candidate, &rule.pattern)
    }
}

fn path_is_below_pattern(path: &str, pattern: &str) -> bool {
    path.strip_prefix(pattern)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_explicitly_git_included(relative: &str, rules: &[GitIgnoreRule]) -> bool {
    let normalized = normalize_path(relative);
    rules.iter().rev().any(|rule| {
        if !rule.negated
            || (!rule.base.is_empty()
                && normalized != rule.base
                && !normalized.starts_with(&format!("{}/", rule.base)))
        {
            return false;
        }
        let local = if rule.base.is_empty() {
            normalized.as_ref()
        } else if normalized == rule.base {
            ""
        } else {
            &normalized[rule.base.len() + 1..]
        };
        rule.matcher.is_match(local)
            || local
                .split('/')
                .any(|segment| rule.matcher.is_match(segment))
    })
}

fn decode_source(
    mut bytes: Vec<u8>,
    relative: &str,
    coverage: &mut BTreeMap<String, usize>,
    diagnostics: &mut Vec<ProcessingDiagnostic>,
) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(&bytes, true);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16(&bytes, false);
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        bytes.drain(..3);
    }
    match String::from_utf8(bytes) {
        Ok(source) => source,
        Err(error) => {
            *coverage.entry("malformed_encoding".to_owned()).or_default() += 1;
            diagnostics.push(ProcessingDiagnostic {
                code: "malformed-utf8",
                severity: "warning",
                stage: "source-decoding",
                message: "Invalid UTF-8 bytes were replaced during source decoding.".to_owned(),
                path: relative.to_owned(),
            });
            String::from_utf8_lossy(&error.into_bytes()).into_owned()
        }
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let (pairs, _) = bytes[2..].as_chunks::<2>();
    let code_units = pairs
        .iter()
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes(*pair)
            } else {
                u16::from_be_bytes(*pair)
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&code_units)
}

fn changed_files(root: &Path, base: &str) -> BTreeSet<String> {
    if base.is_empty() || base.starts_with('-') {
        return BTreeSet::new();
    }
    let mut changed = BTreeSet::new();
    add_git_paths(
        &mut changed,
        root,
        Command::new("git")
            .args(["-C"])
            .arg(root)
            .args(["diff", "--name-only", base, "--"])
            .output(),
    );
    if base == "HEAD" {
        add_git_paths(
            &mut changed,
            root,
            Command::new("git")
                .args(["-C"])
                .arg(root)
                .args(["ls-files", "--others", "--exclude-standard"])
                .output(),
        );
    }
    changed
}

fn add_git_paths(
    changed: &mut BTreeSet<String>,
    root: &Path,
    output: std::io::Result<std::process::Output>,
) {
    let Ok(output) = output else {
        return;
    };
    if !output.status.success() {
        return;
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let relative = line.trim().replace('\\', "/");
        if !relative.is_empty() && root.join(&relative).is_file() {
            changed.insert(relative);
        }
    }
}

fn changed_line_ranges(root: &Path, base: Option<&str>) -> BTreeMap<String, Vec<ChangedLineRange>> {
    let Some(base) = base.filter(|base| !base.is_empty() && !base.starts_with('-')) else {
        return BTreeMap::new();
    };
    let mut ranges = BTreeMap::new();
    add_untracked_line_ranges(root, base, &mut ranges);
    add_diff_line_ranges(root, base, &mut ranges);
    ranges
}

fn add_untracked_line_ranges(
    root: &Path,
    base: &str,
    ranges: &mut BTreeMap<String, Vec<ChangedLineRange>>,
) {
    if base != "HEAD" {
        return;
    }
    let Ok(output) = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    for raw_path in String::from_utf8_lossy(&output.stdout).lines() {
        add_untracked_line_range(root, raw_path, ranges);
    }
}

fn add_untracked_line_range(
    root: &Path,
    raw_path: &str,
    ranges: &mut BTreeMap<String, Vec<ChangedLineRange>>,
) {
    let relative = raw_path.trim().replace('\\', "/");
    let path = root.join(&relative);
    if relative.is_empty() || !path.is_file() {
        return;
    }
    let line_count = fs::read_to_string(path)
        .map(|source| source.lines().count().max(1))
        .unwrap_or(1);
    ranges.insert(
        relative,
        vec![ChangedLineRange {
            start: 1,
            end: line_count,
        }],
    );
}

fn add_diff_line_ranges(
    root: &Path,
    base: &str,
    ranges: &mut BTreeMap<String, Vec<ChangedLineRange>>,
) {
    let Ok(output) = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["diff", "--unified=0", base, "--"])
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    parse_diff_line_ranges(&String::from_utf8_lossy(&output.stdout), ranges);
}

fn parse_diff_line_ranges(diff: &str, ranges: &mut BTreeMap<String, Vec<ChangedLineRange>>) {
    let mut current = None;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            current = Some(path.trim());
        } else if let (Some(path), Some(range)) = (current, parse_diff_hunk(line)) {
            let normalized = path.replace('\\', "/");
            if !normalized.is_empty() {
                ranges.entry(normalized).or_default().push(range);
            }
        }
    }
}

fn parse_diff_hunk(line: &str) -> Option<ChangedLineRange> {
    let captures = DIFF_HUNK.captures(line)?;
    let start = captures.get(1)?.as_str().parse::<usize>().ok()?;
    let count = captures
        .get(2)
        .map(|value| value.as_str().parse::<usize>())
        .transpose()
        .ok()?
        .unwrap_or(1);
    if count == 0 {
        return None;
    }
    Some(ChangedLineRange {
        start,
        end: start + count - 1,
    })
}

fn relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|error| format!("failed to relativize {}: {error}", path.display()))?
        .to_str()
        .map(|value| {
            let normalized = value.replace('\\', "/");
            if normalized.is_empty() {
                ".".to_owned()
            } else {
                normalized
            }
        })
        .ok_or_else(|| format!("path must be valid UTF-8: {}", path.display()))
}

fn normalize_path(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

fn normalize_classification_path(path: &str) -> Cow<'_, str> {
    if path
        .bytes()
        .any(|byte| byte == b'\\' || byte.is_ascii_uppercase())
    {
        Cow::Owned(path.replace('\\', "/").to_ascii_lowercase())
    } else {
        Cow::Borrowed(path)
    }
}

fn extension(path: &Path) -> &str {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
}

fn relative_with_slash(relative: &str) -> String {
    format!("{relative}/")
}

fn is_default_ignored_directory(name: &str, relative: &str) -> bool {
    let ignored = [
        ".git",
        ".svn",
        "node_modules",
        "obj",
        "dist",
        "build",
        ".idea",
        ".vscode",
    ];
    ignored.contains(&name) && !(name == "build" && is_source_build_directory(relative))
}

fn is_source_build_directory(relative: &str) -> bool {
    let segments = relative
        .replace('\\', "/")
        .to_ascii_lowercase()
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    segments.last().is_some_and(|value| value == "build")
        && segments
            .get(segments.len().saturating_sub(2))
            .is_some_and(|value| ["command", "commands", "cmd", "cmds"].contains(&value.as_str()))
}
fn looks_binary(extension: &str) -> bool {
    extension_matches(
        extension,
        &[
            "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "pdf", "zip", "gz", "tar", "jar",
            "dll", "so", "dylib", "exe", "wasm",
        ],
    )
}

fn looks_like_unsupported_source(extension: &str) -> bool {
    extension_matches(
        extension,
        &[
            "go", "kt", "kts", "swift", "rs", "php", "rb", "scala", "ex", "exs", "fs", "fsx", "vb",
            "r", "jl", "zig", "m", "mm",
        ],
    )
}

fn extension_matches(extension: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

fn has_lua_shebang(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut bytes = [0_u8; 256];
    let Ok(length) = file.read(&mut bytes) else {
        return false;
    };
    if length == 0 || bytes[..length].contains(&0) {
        return false;
    }
    let first_line = String::from_utf8_lossy(&bytes[..length]);
    let first_line = first_line.lines().next().unwrap_or_default();
    let Some(captures) = LUA_SHEBANG_REGEX.captures(first_line) else {
        return false;
    };
    let mut interpreter = captures.get(1).map_or("", |value| value.as_str());
    if interpreter.rsplit('/').next() == Some("env") {
        let arguments = captures
            .get(2)
            .map_or("", |value| value.as_str())
            .split_whitespace()
            .collect::<Vec<_>>();
        let command_index = usize::from(arguments.first() == Some(&"-S"));
        let Some(command) = arguments.get(command_index) else {
            return false;
        };
        interpreter = command;
    }
    LUA_COMMAND_REGEX.is_match(interpreter.rsplit('/').next().unwrap_or_default())
}

const GENERATED_FILE_SUFFIXES: &[&str] = &[
    ".g.dart",
    ".freezed.dart",
    ".pb.dart",
    ".pbenum.dart",
    ".pbjson.dart",
    ".pbserver.dart",
    ".designer.cs",
    ".generated.cs",
    ".g.cs",
    ".g.i.cs",
    ".min.js",
    ".min.css",
    ".gen.dart",
    ".mocks.dart",
    ".gr.dart",
];
const TREE_SITTER_GENERATED: &[&str] = &[
    "/tree_sitter/parser.h",
    "/tree_sitter/alloc.h",
    "/tree_sitter/array.h",
];

fn is_generated_by_name(relative: &str) -> bool {
    let lower = relative.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or_default();
    name.contains("_generated.")
        || GENERATED_FILE_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        || is_generated_web_name(name)
        || is_localization_output(name)
        || TREE_SITTER_GENERATED
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}

fn is_generated_web_name(name: &str) -> bool {
    BACKUP_WEB_REGEX.is_match(name)
        || GENERATED_WEB_REGEX.is_match(name)
        || HASHED_WEB_REGEX.is_match(name)
}

fn is_localization_output(name: &str) -> bool {
    name == "app_localizations.dart"
        || name.starts_with("app_localizations_") && name.ends_with(".dart")
}

fn has_generated_header(path: &Path) -> Result<bool, String> {
    let mut file =
        File::open(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut bytes = vec![0_u8; 4096];
    let length = file
        .read(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(has_generated_header_bytes(&bytes[..length]))
}

fn has_generated_header_bytes(bytes: &[u8]) -> bool {
    let length = bytes.len().min(4096);
    let header = String::from_utf8_lossy(&bytes[..length]).to_ascii_lowercase();
    is_generated_header(&header)
}

fn is_generated_header(header: &str) -> bool {
    GENERATED_HEADER_REGEX.is_match(header)
        || has_generated_comment_header(header)
        || GENERATED_HEADER_MARKERS
            .iter()
            .any(|marker| header.contains(marker))
        || GENERATED_HEADER_MARKER_GROUPS
            .iter()
            .any(|markers| markers.iter().all(|marker| header.contains(marker)))
}

fn has_generated_comment_header(header: &str) -> bool {
    GENERATED_COMMENT_HEADER_REGEX
        .find_iter(header)
        .any(|marker| {
            header[..marker.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                < 12
        })
}

const GENERATED_HEADER_MARKERS: &[&str] = &[
    "generated code - do not modify",
    "file generated from ",
    "amalgamated source file",
    "this file is an amalgamation of",
    "automatically generated code do not modify",
    "generated file - do not edit",
    "generated file. do not edit",
    "auto generated file, do not edit",
    "this class is generated.",
    "this file is generated.",
    "generated by:javacc",
    "//{{no_dependencies}}",
    "no linting because it's generated code",
    "scanner generated by flex",
    "@generated",
];

const GENERATED_HEADER_MARKER_GROUPS: &[&[&str]] = &[
    &["automatically generated", "do not modify"],
    &["do not edit", "autogenerated"],
    &["do not edit", "auto-generated"],
    &["generated by ", "do not edit"],
    &["generated by ", "do not modify"],
    &[
        "#include \"tree_sitter/parser.h\"",
        "#define language_version ",
        "#define state_count ",
    ],
    &["antlr generated code", "do not edit"],
    &["generated from ", " by antlr "],
    &["emscripten bindings", "eslint-disable", "@ts-nocheck"],
];

fn is_minified_bundle(path: &Path, extension: &str) -> Result<bool, String> {
    if !extension_matches(extension, &["js", "mjs", "cjs", "css"]) {
        return Ok(false);
    }
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if metadata.len() < 2 * 1024 {
        return Ok(false);
    }
    let sample = read_bundle_sample(path, metadata.len())?;
    let stats = BundleSampleStats::from_sample(&sample);
    if stats.indicates_minification(metadata.len()) {
        return Ok(true);
    }
    Ok(is_javascript_bundle(extension) && has_compiled_javascript_markers(&sample, metadata.len()))
}

fn is_minified_bundle_bytes(bytes: &[u8], extension: &str) -> bool {
    if !extension_matches(extension, &["js", "mjs", "cjs", "css"]) || bytes.len() < 2 * 1024 {
        return false;
    }
    let file_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let sample = &bytes[..bytes.len().min(64 * 1024)];
    let stats = BundleSampleStats::from_sample(sample);
    stats.indicates_minification(file_length)
        || (is_javascript_bundle(extension) && has_compiled_javascript_markers(sample, file_length))
}

fn read_bundle_sample(path: &Path, file_length: u64) -> Result<Vec<u8>, String> {
    let sample_length = usize::try_from(file_length.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut file =
        File::open(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut sample = vec![0_u8; sample_length];
    file.read_exact(&mut sample)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(sample)
}

struct BundleSampleStats {
    length: usize,
    lines: usize,
    longest_line: usize,
}

impl BundleSampleStats {
    fn from_sample(sample: &[u8]) -> Self {
        let mut lines = 1;
        let mut current_line = 0;
        let mut longest_line = 0;
        for byte in sample {
            if *byte == b'\n' {
                lines += 1;
                longest_line = longest_line.max(current_line);
                current_line = 0;
            } else {
                current_line += 1;
            }
        }
        Self {
            length: sample.len(),
            lines,
            longest_line: longest_line.max(current_line),
        }
    }

    fn indicates_minification(&self, file_length: u64) -> bool {
        self.longest_line >= 2000 || (file_length >= 20 * 1024 && self.length / self.lines >= 500)
    }
}

fn is_javascript_bundle(extension: &str) -> bool {
    extension_matches(extension, &["js", "mjs", "cjs"])
}

fn has_compiled_javascript_markers(sample: &[u8], file_length: u64) -> bool {
    let source = String::from_utf8_lossy(sample);
    if file_length >= 1024 * 1024
        && source.contains("var __defProp = Object.defineProperty")
        && source.contains("var __copyProps =")
    {
        return true;
    }
    file_length >= 32 * 1024 && javascript_helper_count(&source) >= 4
}

fn javascript_helper_count(source: &str) -> usize {
    [
        "function _arrayLikeToArray(",
        "function _classCallCheck(",
        "function _createClass(",
        "function _createForOfIteratorHelper(",
        "function _defineProperties(",
        "function _iterableToArrayLimit(",
    ]
    .iter()
    .filter(|helper| source.contains(**helper))
    .count()
}

static DIFF_HUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
        .expect("Git diff hunk regex must compile")
});
static TEST_FILE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:_tests?\.(?:dart|go|py|rs)|(?:^|_)tests?\.rs|_spec\.rb|\.(?:test|spec)\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)|tests?\.java|\.snap)$").unwrap()
});
static BACKUP_FILE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.backup\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$").unwrap());
static TEST_HELPER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:test_?util|test_?helpers?)\.[^.]+$").unwrap());
static SRC_TEST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|/)src/[^/]*test(?:fixtures)?(?:/|$)").unwrap());
static LUA_SHEBANG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#!\s*(\S+)(?:\s+(.*))?$").unwrap());
static LUA_COMMAND_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:lua(?:5\.[1-4])?|luajit(?:2\.\d+)?|resty)$").unwrap());
static BACKUP_WEB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.backup\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$").unwrap());
static GENERATED_WEB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.gen\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$").unwrap());
static HASHED_WEB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-[0-9a-f]{8,}\.(?:js|css)$").unwrap());
static VERSIONED_VENDOR_ASSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[a-z0-9_-]+@\d+(?:\.\d+){0,2}(?:\.min)?\.(?:css|js)$").unwrap()
});
static GENERATED_HEADER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?://|/\*)\s*(?:generated code with\b|do not change[,;:]?\s+this code is generated\b)").unwrap()
});
static GENERATED_COMMENT_HEADER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?mi)^[ \t]*//[ \t]*(?:<auto-generated(?:[ \t]*/)?[ \t]*>|[^\n]*\bgenerated file\b[^\n]*\bdo not manually edit\b)",
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::{RepositoryPolicy, SourceRole, classify_path, is_generated_header};

    #[test]
    fn recognizes_simple_and_compound_generated_headers() {
        assert!(is_generated_header("// generated file - do not edit"));
        assert!(is_generated_header(
            "// Licensed source\n// <auto-generated />"
        ));
        assert!(is_generated_header(
            "// Licensed source\n\n// NOTE: This is a generated file - do not manually edit!"
        ));
        assert!(is_generated_header(
            "#include \"tree_sitter/parser.h\"\n#define language_version 14\n#define state_count 25"
        ));
        assert!(is_generated_header(
            "// emscripten bindings\n/* eslint-disable */\n// @ts-nocheck"
        ));
        assert!(is_generated_header("/* amalgamated source file */"));
        assert!(is_generated_header(
            "// this file is an amalgamation of multiple different files.\n\
             // you probably shouldn't edit it directly."
        ));
        assert!(!is_generated_header(
            "// automatically generated documentation"
        ));
        assert!(!is_generated_header("// generated by maintainers"));
        assert!(!is_generated_header(
            "class Emitter {\n  void Write() {\n    writer.WriteLine(\"// <auto-generated/>\");\n  }\n}"
        ));
        let late_raw_marker = format!("{}// <auto-generated/>", "\n".repeat(12));
        assert!(!is_generated_header(&late_raw_marker));
    }

    #[test]
    fn classifies_packaged_test_support_as_test_code() {
        for path in [
            "devel-common/src/tests_common/pytest_plugin.py",
            "pkgs/http_client_conformance_tests/lib/src/abort_server.dart",
            "lib/src/abort_tests.dart",
        ] {
            assert_eq!(
                classify_path(path, &RepositoryPolicy::default()),
                SourceRole::Test,
                "{path}"
            );
        }
        assert_eq!(
            classify_path(
                "src/common_testing/runtime.py",
                &RepositoryPolicy::default()
            ),
            SourceRole::Production
        );
    }

    #[test]
    fn classifies_playgrounds_benchmarks_and_named_examples() {
        for path in [
            "playground/worker/main.ts",
            "tools/playgrounds/parser/main.js",
            "scripts/benchmark.js",
            "tools/bench.ts",
            "tasks/micro-benchmark/src/main.rs",
            "tasks/integrated-benchmark/src/main.rs",
            "modules/core/src/jmh/java/org/example/ParserBenchmark.java",
            "framework-docs/src/main/java/org/example/Example.java",
            "pkgs/flutter_http_example/lib/main.dart",
            "docs/html-formatter-example.html",
            "packages/example-server/src/main.ts",
        ] {
            assert_eq!(
                classify_path(path, &RepositoryPolicy::default()),
                SourceRole::Example,
                "{path}"
            );
        }
    }

    #[test]
    fn keeps_example_named_production_source_files() {
        for path in [
            "src/cargo_example.rs",
            "docs/tools/markdown-it-rule-example.js",
            "src/example-server.ts",
        ] {
            assert_eq!(
                classify_path(path, &RepositoryPolicy::default()),
                SourceRole::Production,
                "{path}"
            );
        }
    }

    #[test]
    fn classifies_versioned_web_assets_as_vendored() {
        assert_eq!(
            classify_path(
                "docs/assets/css-vars-ponyfill@2.js",
                &RepositoryPolicy::default()
            ),
            SourceRole::Vendored
        );
    }

    #[test]
    fn excludes_file_level_examples_and_vendored_assets_unless_requested() {
        assert!(super::excludes_source_role(
            SourceRole::Example,
            false,
            false,
            false,
            false
        ));
        assert!(super::excludes_source_role(
            SourceRole::Vendored,
            false,
            false,
            false,
            false
        ));
        assert!(!super::excludes_source_role(
            SourceRole::Example,
            false,
            false,
            true,
            false
        ));
        assert!(!super::excludes_source_role(
            SourceRole::Vendored,
            false,
            false,
            false,
            true
        ));
    }

    #[test]
    fn preserves_production_and_test_support_classification() {
        assert_eq!(
            classify_path("src/resolve_latest.rs", &RepositoryPolicy::default()),
            SourceRole::Production
        );
        assert_eq!(
            classify_path(
                "pnpr/.fixtures/package/package.json",
                &RepositoryPolicy::default()
            ),
            SourceRole::Test
        );

        for path in [
            "crates/testing-utils/src/lib.rs",
            "crates/pnpr-fixtures/src/lib.rs",
            "tasks/ecosystem-e2e/src/main.rs",
        ] {
            assert_eq!(
                classify_path(path, &RepositoryPolicy::default()),
                SourceRole::Test,
                "{path}"
            );
        }
    }
}
