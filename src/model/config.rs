use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use toml::Value;

pub const STARTER_CONFIG: &str = "# Optional repository-specific overrides.\n# Code Buster already detects languages, frameworks, generated files, and\n# production source conventions when this file is absent.\nlanguages = [\"auto\"]\n";

use crate::cli::PreviewOptions;
use crate::findings::Severity;

pub type Table = toml::map::Map<String, Value>;
#[derive(Clone, Debug)]
pub struct PatternRule {
    pub id: String,
    pub severity: Severity,
    pub pattern: String,
    pub message: String,
    pub suggestion: String,
    pub pattern_not: String,
    pub fix: String,
    pub category: String,
}

struct SeveritySettings {
    disabled_rules: BTreeSet<String>,
    overrides: BTreeMap<String, String>,
    order: Vec<(String, String)>,
}

const DEFAULT_GROUPS: &[&str] = &[
    "correctness",
    "core",
    "security",
    "reliability",
    "accessibility",
    "performance",
    "maintainability",
    "style",
    "nim-style",
    "suspicious",
    "design",
    "yagni",
    "regex",
    "sql",
    "idiomatic",
    "nim-advanced",
    "strings",
    "zerocost",
];

const SEMANTIC_GROUPS: &[&str] = &[
    "correctness",
    "security",
    "reliability",
    "accessibility",
    "performance",
    "maintainability",
    "style",
    "suspicious",
    "architecture",
    "domain",
    "experimental",
];

#[derive(Clone, Debug)]
pub struct Config {
    pub root: PathBuf,
    pub language: String,
    pub languages: Vec<String>,
    pub frameworks: BTreeSet<String>,
    pub entry_points: Vec<String>,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub changed_base: Option<String>,
    pub changed_lines: bool,
    pub ignore_patterns: Vec<String>,
    pub classification_production: Vec<String>,
    pub classification_test: Vec<String>,
    pub classification_generated: Vec<String>,
    pub min_duplication_lines: i64,
    pub duplication_mode: String,
    pub complexity_threshold: i64,
    pub cognitive_threshold: i64,
    pub max_file_lines: i64,
    // Parsed now because these settings are part of the shared analysis contract.
    #[allow(dead_code)]
    pub max_function_lines: i64,
    #[allow(dead_code)]
    pub csharp_dead_code: bool,
    pub quality_profile: String,
    pub quality_gates: Vec<String>,
    pub rule_groups: BTreeSet<String>,
    pub disabled_rules: BTreeSet<String>,
    #[allow(dead_code)]
    pub severity_overrides: BTreeMap<String, String>,
    pub severity_override_order: Vec<(String, String)>,
    pub group_modes: BTreeMap<String, String>,
    pub rule_modes: BTreeMap<String, String>,
    pub pattern_rules: Vec<PatternRule>,
    pub structure_source_roots: Vec<String>,
    pub structure_max_top_level_files: i64,
    pub structure_allowed_top_level: Vec<String>,
    pub structure_required_directories: Vec<String>,
    pub architecture_layers: Vec<String>,
    pub architecture_allowed_dependencies: Vec<String>,
    pub architecture_denied_dependencies: Vec<String>,
    pub architecture_profile: String,
    pub mvvm_views: Vec<String>,
    pub mvvm_view_models: Vec<String>,
    pub mvvm_models: Vec<String>,
    pub mvvm_repositories: Vec<String>,
    pub mvvm_strict_view_model_boundary: bool,
    pub include_all: bool,
    pub include_tests: bool,
    pub include_examples: bool,
    pub include_vendored: bool,
}

impl Config {
    pub fn defaults(root: PathBuf) -> Self {
        Self {
            root,
            language: "auto".to_owned(),
            languages: Vec::new(),
            frameworks: BTreeSet::new(),
            entry_points: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            changed_base: None,
            changed_lines: false,
            ignore_patterns: Vec::new(),
            classification_production: Vec::new(),
            classification_test: Vec::new(),
            classification_generated: Vec::new(),
            min_duplication_lines: 15,
            duplication_mode: "exact".to_owned(),
            complexity_threshold: 10,
            cognitive_threshold: 15,
            max_file_lines: 0,
            max_function_lines: 0,
            csharp_dead_code: false,
            quality_profile: "standard".to_owned(),
            quality_gates: vec!["findings == 0".to_owned()],
            rule_groups: DEFAULT_GROUPS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            disabled_rules: BTreeSet::new(),
            severity_overrides: BTreeMap::new(),
            severity_override_order: Vec::new(),
            group_modes: BTreeMap::new(),
            rule_modes: BTreeMap::new(),
            pattern_rules: Vec::new(),
            structure_source_roots: Vec::new(),
            structure_max_top_level_files: -1,
            structure_allowed_top_level: Vec::new(),
            structure_required_directories: Vec::new(),
            architecture_layers: Vec::new(),
            architecture_allowed_dependencies: Vec::new(),
            architecture_denied_dependencies: Vec::new(),
            architecture_profile: String::new(),
            mvvm_views: Vec::new(),
            mvvm_view_models: Vec::new(),
            mvvm_models: Vec::new(),
            mvvm_repositories: Vec::new(),
            mvvm_strict_view_model_boundary: true,
            include_all: false,
            include_tests: false,
            include_examples: false,
            include_vendored: false,
        }
    }

    pub fn load_from_root(root: PathBuf) -> Result<Self, String> {
        let path = root.join("code-buster.toml");
        if !path.exists() {
            return Ok(Self::defaults(root));
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let values = parse_document(&source)?;
        Self::from_document(root, &values)
    }

    fn from_document(root: PathBuf, values: &Table) -> Result<Self, String> {
        let sections = ConfigSections::read(values)?;
        let quality_profile =
            string(sections.quality, "profile")?.unwrap_or_else(|| "standard".to_owned());
        let strict = quality_profile == "strict";
        let configured_groups = preferred_string_list(
            sections.rules,
            "enabled_groups",
            Some(values),
            "rule_groups",
        )?;
        let mut group_modes = rule_modes(table(sections.rules, "groups")?, true)?;
        apply_legacy_group_modes(&mut group_modes, &configured_groups);

        let architecture = ArchitectureSettings::read(&sections)?;
        enable_architecture_group(&mut group_modes, &architecture);

        let rule_modes = rule_modes(table(sections.rules, "mode")?, false)?;
        let severity = read_severity_settings(&sections)?;
        let rules = RuleSettings::collect(configured_groups, group_modes, rule_modes, severity);
        let quality_gates = quality_gates(sections.quality, &quality_profile)?;
        let pattern_rules = read_pattern_rules(sections.rules, values)?;
        let (allowed, required) = read_structure_aliases(sections.structure)?;

        Ok(Self {
            root,
            language: string(Some(values), "lang")?.unwrap_or_else(|| "auto".to_owned()),
            languages: string_list(Some(values), "languages")?,
            frameworks: BTreeSet::new(),
            entry_points: preferred_string_list(
                sections.files,
                "entry_points",
                Some(values),
                "entry_points",
            )?,
            includes: string_list(sections.files, "include")?,
            excludes: string_list(sections.files, "exclude")?,
            changed_base: string(sections.review, "changed_base")?
                .filter(|value| !value.is_empty()),
            changed_lines: false,
            ignore_patterns: preferred_string_list(
                sections.files,
                "ignore",
                Some(values),
                "ignore_patterns",
            )?,
            classification_production: string_list(sections.classification, "production")?,
            classification_test: string_list(sections.classification, "test")?,
            classification_generated: string_list(sections.classification, "generated")?,
            min_duplication_lines: preferred_integer(
                sections.analysis,
                "duplication_min_lines",
                Some(values),
                "min_duplication_lines",
                if strict { 10 } else { 15 },
            )?,
            duplication_mode: string(sections.analysis, "duplication_mode")?
                .unwrap_or_else(|| "exact".to_owned()),
            complexity_threshold: preferred_integer(
                sections.analysis,
                "complexity_threshold",
                Some(values),
                "complexity_threshold",
                if strict { 8 } else { 10 },
            )?,
            cognitive_threshold: preferred_integer(
                sections.analysis,
                "cognitive_complexity_threshold",
                Some(values),
                "cognitive_threshold",
                if strict { 12 } else { 15 },
            )?,
            max_file_lines: preferred_integer(
                sections.analysis,
                "max_file_lines",
                Some(values),
                "max_file_lines",
                0,
            )?,
            max_function_lines: preferred_integer(
                sections.analysis,
                "max_function_lines",
                Some(values),
                "max_function_lines",
                0,
            )?,
            csharp_dead_code: preferred_boolean(
                sections.analysis,
                "csharp_dead_code",
                Some(values),
                "csharp_dead_code",
                false,
            )?,
            quality_profile,
            quality_gates,
            rule_groups: rules.groups,
            disabled_rules: rules.disabled,
            severity_overrides: rules.severity_overrides,
            severity_override_order: rules.severity_order,
            group_modes: rules.group_modes,
            rule_modes: rules.rule_modes,
            pattern_rules,
            structure_source_roots: read_structure_source_roots(sections.structure, values)?,
            structure_max_top_level_files: read_structure_max_files(sections.structure, values)?,
            structure_allowed_top_level: fallback_list(
                allowed,
                Some(values),
                "structure_allowed_top_level",
            )?,
            structure_required_directories: fallback_list(
                required,
                Some(values),
                "structure_required_dirs",
            )?,
            architecture_layers: architecture.layers,
            architecture_allowed_dependencies: architecture.allowed_dependencies,
            architecture_denied_dependencies: architecture.denied_dependencies,
            architecture_profile: architecture.profile,
            mvvm_views: string_list(sections.mvvm, "views")?,
            mvvm_view_models: string_list(sections.mvvm, "view_models")?,
            mvvm_models: string_list(sections.mvvm, "models")?,
            mvvm_repositories: string_list(sections.mvvm, "repositories")?,
            mvvm_strict_view_model_boundary: boolean(
                sections.mvvm,
                "strict_view_model_boundary",
                true,
            )?,
            include_all: false,
            include_tests: false,
            include_examples: false,
            include_vendored: false,
        })
    }

    pub fn load(root: PathBuf, options: &PreviewOptions) -> Result<Self, String> {
        let mut config = Self::load_from_root(root)?;
        if let Some(language) = &options.language {
            config.language.clone_from(language);
        }
        if !options.languages.is_empty() {
            config.languages.clone_from(&options.languages);
        }
        if !options.includes.is_empty() {
            config.includes.clone_from(&options.includes);
        }
        if !options.excludes.is_empty() {
            config.excludes.clone_from(&options.excludes);
        }
        if options.changed_base.is_some() {
            config.changed_base.clone_from(&options.changed_base);
        }
        config.changed_lines = options.changed_lines;
        config.include_all = options.include_all;
        config.include_tests = options.include_tests;
        config.include_examples = options.include_examples;
        config.include_vendored = options.include_vendored;
        Ok(config)
    }

    pub fn dart_mvvm_enabled(&self) -> bool {
        self.architecture_profile == "dart-mvvm"
    }
}

struct ConfigSections<'a> {
    analysis: Option<&'a Table>,
    files: Option<&'a Table>,
    rules: Option<&'a Table>,
    classification: Option<&'a Table>,
    review: Option<&'a Table>,
    quality: Option<&'a Table>,
    architecture: Option<&'a Table>,
    mvvm: Option<&'a Table>,
    structure: Option<&'a Table>,
    legacy_severity: Option<&'a Table>,
    rule_severity: Option<&'a Table>,
}

impl<'a> ConfigSections<'a> {
    fn read(values: &'a Table) -> Result<Self, String> {
        let analysis = table(Some(values), "analysis")?;
        let files = table(Some(values), "files")?;
        let rules = table(Some(values), "rules")?;
        let classification = table(Some(values), "classification")?;
        let review = table(Some(values), "review")?;
        let quality = table(Some(values), "quality")?;
        let architecture = table(Some(values), "architecture")?;
        let mvvm = table(architecture, "mvvm")?;
        let structure = table(Some(values), "structure")?;
        let legacy_severity = table(Some(values), "severity")?;
        let rule_severity = table(rules, "severity")?;
        Ok(Self {
            analysis,
            files,
            rules,
            classification,
            review,
            quality,
            architecture,
            mvvm,
            structure,
            legacy_severity,
            rule_severity,
        })
    }
}

struct ArchitectureSettings {
    profile: String,
    layers: Vec<String>,
    allowed_dependencies: Vec<String>,
    denied_dependencies: Vec<String>,
}

impl ArchitectureSettings {
    fn read(sections: &ConfigSections<'_>) -> Result<Self, String> {
        Ok(Self {
            profile: string(sections.architecture, "profile")?.unwrap_or_default(),
            layers: string_list(sections.architecture, "layers")?,
            allowed_dependencies: string_list(sections.architecture, "allowed_dependencies")?,
            denied_dependencies: string_list(sections.architecture, "denied_dependencies")?,
        })
    }

    fn is_configured(&self) -> bool {
        !self.profile.is_empty()
            || !self.layers.is_empty()
            || !self.allowed_dependencies.is_empty()
            || !self.denied_dependencies.is_empty()
    }
}

struct RuleSettings {
    groups: BTreeSet<String>,
    disabled: BTreeSet<String>,
    severity_overrides: BTreeMap<String, String>,
    severity_order: Vec<(String, String)>,
    group_modes: BTreeMap<String, String>,
    rule_modes: BTreeMap<String, String>,
}

impl RuleSettings {
    fn collect(
        configured_groups: Vec<String>,
        group_modes: BTreeMap<String, String>,
        rule_modes: BTreeMap<String, String>,
        severity: SeveritySettings,
    ) -> Self {
        let SeveritySettings {
            mut disabled_rules,
            overrides,
            order,
        } = severity;
        disabled_rules.extend(
            rule_modes
                .iter()
                .filter(|(_, mode)| mode.as_str() == "off")
                .map(|(rule, _)| rule.clone()),
        );

        let mut groups = DEFAULT_GROUPS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        groups.extend(configured_groups);
        groups.extend(
            group_modes
                .iter()
                .filter(|(_, mode)| mode.as_str() != "off")
                .map(|(group, _)| group.clone()),
        );
        groups.retain(|group| group_modes.get(group).is_none_or(|mode| mode != "off"));

        Self {
            groups,
            disabled: disabled_rules,
            severity_overrides: overrides,
            severity_order: order,
            group_modes,
            rule_modes,
        }
    }
}

fn apply_legacy_group_modes(
    group_modes: &mut BTreeMap<String, String>,
    configured_groups: &[String],
) {
    for group in configured_groups {
        for semantic in semantic_groups_for_legacy(group) {
            group_modes.insert((*semantic).to_owned(), "report".to_owned());
        }
    }
}

fn enable_architecture_group(
    group_modes: &mut BTreeMap<String, String>,
    architecture: &ArchitectureSettings,
) {
    if architecture.is_configured() {
        group_modes.insert("architecture".to_owned(), "report".to_owned());
    }
}

fn read_severity_settings(sections: &ConfigSections<'_>) -> Result<SeveritySettings, String> {
    let values = if sections.rule_severity.is_none_or(Table::is_empty) {
        sections.legacy_severity
    } else {
        sections.rule_severity
    };
    severity_settings(values)
}

fn quality_gates(quality: Option<&Table>, profile: &str) -> Result<Vec<String>, String> {
    let configured = string_list(quality, "gates")?;
    if !configured.is_empty() {
        return Ok(configured);
    }
    Ok(match profile {
        "strict" => vec![
            "findings == 0".to_owned(),
            "debt_minutes_per_file <= 5".to_owned(),
        ],
        "security" => vec!["security_vulnerabilities == 0".to_owned()],
        _ => vec!["findings == 0".to_owned()],
    })
}

fn read_pattern_rules(rules: Option<&Table>, values: &Table) -> Result<Vec<PatternRule>, String> {
    preferred_string_list(rules, "patterns", Some(values), "pattern_rules")?
        .into_iter()
        .filter_map(|rule| parse_pattern_rule(&rule).transpose())
        .collect()
}

fn read_structure_aliases(structure: Option<&Table>) -> Result<(Vec<String>, Vec<String>), String> {
    let allowed = preferred_string_list(
        structure,
        "allowed_root_files",
        structure,
        "allowed_top_level",
    )?;
    let required = preferred_string_list(
        structure,
        "required_directories",
        structure,
        "required_dirs",
    )?;
    Ok((allowed, required))
}

fn read_structure_source_roots(
    structure: Option<&Table>,
    values: &Table,
) -> Result<Vec<String>, String> {
    fallback_list(
        string_list(structure, "source_roots")?,
        Some(values),
        "structure_source_roots",
    )
}

fn read_structure_max_files(structure: Option<&Table>, values: &Table) -> Result<i64, String> {
    let legacy = integer(Some(values), "structure_max_top_level_files", -1)?;
    preferred_integer(
        structure,
        "max_root_files",
        structure,
        "max_top_level_files",
        legacy,
    )
}

fn fallback_list(
    preferred: Vec<String>,
    legacy_parent: Option<&Table>,
    legacy_key: &str,
) -> Result<Vec<String>, String> {
    if preferred.is_empty() {
        string_list(legacy_parent, legacy_key)
    } else {
        Ok(preferred)
    }
}

pub fn parse_document(source: &str) -> Result<Table, String> {
    normalize_legacy_pipe_escapes(source)
        .parse::<Table>()
        .map_err(|error| format!("invalid TOML: {error}"))
}

const CONFIG_SCHEMA: &[(&str, &[&str])] = &[
    (
        "analysis",
        &[
            "duplication_min_lines",
            "duplication_mode",
            "complexity_threshold",
            "cognitive_complexity_threshold",
            "max_file_lines",
            "max_function_lines",
            "csharp_dead_code",
        ],
    ),
    ("files", &["include", "exclude", "ignore", "entry_points"]),
    ("classification", &["production", "test", "generated"]),
    (
        "rules",
        &["enabled_groups", "groups", "mode", "patterns", "severity"],
    ),
    (
        "structure",
        &[
            "source_roots",
            "max_root_files",
            "max_top_level_files",
            "allowed_root_files",
            "allowed_top_level",
            "required_directories",
            "required_dirs",
        ],
    ),
    (
        "architecture",
        &[
            "profile",
            "layers",
            "allowed_dependencies",
            "denied_dependencies",
            "mvvm",
        ],
    ),
    ("review", &["changed_base", "fail_on_findings"]),
    ("quality", &["profile", "gates"]),
];

const LEGACY_CONFIG_KEYS: &[&str] = &[
    "lang",
    "entry_points",
    "ignore_patterns",
    "min_duplication_lines",
    "complexity_threshold",
    "cognitive_threshold",
    "max_file_lines",
    "max_function_lines",
    "csharp_dead_code",
    "rule_groups",
    "pattern_rules",
    "severity",
    "structure_source_roots",
    "structure_max_top_level_files",
    "structure_allowed_top_level",
    "structure_required_dirs",
];

const MVVM_KEYS: &[&str] = &[
    "views",
    "view_models",
    "models",
    "repositories",
    "strict_view_model_boundary",
];

struct ConfigValidation<'a> {
    values: &'a Table,
    diagnostics: Vec<String>,
}

impl<'a> ConfigValidation<'a> {
    fn collect(values: &'a Table) -> Vec<String> {
        let mut validation = Self {
            values,
            diagnostics: Vec::new(),
        };
        validation.check_schema();
        validation.check_quality();
        validation.check_duplication_mode();
        validation.check_architecture();
        validation.check_typed_fields();
        validation.diagnostics
    }

    fn check_schema(&mut self) {
        for (key, value) in self.values {
            if key == "languages" || LEGACY_CONFIG_KEYS.contains(&key.as_str()) {
                continue;
            }
            let Some((_, accepted)) = CONFIG_SCHEMA.iter().find(|(name, _)| name == key) else {
                self.diagnostics
                    .push(format!("unknown configuration key: {key}"));
                continue;
            };
            let Some(values) = value.as_table() else {
                self.diagnostics.push(format!("expected table: {key}"));
                continue;
            };
            for nested in values.keys() {
                if !accepted.contains(&nested.as_str()) {
                    self.diagnostics
                        .push(format!("unknown configuration key: {key}.{nested}"));
                }
            }
        }
    }

    fn check_quality(&mut self) {
        let quality = self.values.get("quality").and_then(Value::as_table);
        let profile = value_string(quality, "profile").unwrap_or("standard");
        if !["standard", "strict", "security"].contains(&profile) {
            self.diagnostics
                .push(format!("unsupported quality profile: {profile}"));
        }
        let Some(gates) = quality
            .and_then(|table| table.get("gates"))
            .and_then(Value::as_array)
        else {
            return;
        };
        let Ok(pattern) =
            Regex::new(r"^\s*[a-z][a-z0-9_.]*\s*(?:==|!=|<=|>=|<|>)\s*\d+(?:\.\d+)?\s*$")
        else {
            return;
        };
        for gate in gates.iter().filter_map(Value::as_str) {
            if !pattern.is_match(gate) {
                self.diagnostics
                    .push(format!("unsupported quality gate condition: {gate}"));
            }
        }
    }

    fn check_duplication_mode(&mut self) {
        let mode = self
            .values
            .get("analysis")
            .and_then(Value::as_table)
            .and_then(|table| value_string(Some(table), "duplication_mode"))
            .unwrap_or("exact");
        if !["exact", "normalized", "semantic"].contains(&mode) {
            self.diagnostics
                .push(format!("unsupported duplication mode: {mode}"));
        }
    }

    fn check_architecture(&mut self) {
        let architecture = self.values.get("architecture").and_then(Value::as_table);
        let profile = value_string(architecture, "profile").unwrap_or("");
        if !profile.is_empty() && profile != "dart-mvvm" {
            self.diagnostics
                .push(format!("unsupported architecture profile: {profile}"));
        }
        let Some(mvvm) = architecture
            .and_then(|table| table.get("mvvm"))
            .and_then(Value::as_table)
        else {
            return;
        };
        for key in mvvm.keys() {
            if !MVVM_KEYS.contains(&key.as_str()) {
                self.diagnostics.push(format!(
                    "unknown configuration key: architecture.mvvm.{key}"
                ));
            }
        }
    }

    fn check_typed_fields(&mut self) {
        if let Err(error) = Config::from_document(PathBuf::from("."), self.values) {
            self.diagnostics.push(format!("FormatException: {error}"));
        }
    }
}

pub fn validate(source: &str) -> Vec<String> {
    match parse_document(source) {
        Ok(values) => ConfigValidation::collect(&values),
        Err(error) => vec![error],
    }
}

#[derive(Clone, Copy)]
enum MigrationSection {
    Root,
    Structure,
    Other,
}

impl MigrationSection {
    fn from_header(header: &str) -> Self {
        match header {
            "" => Self::Root,
            "structure" => Self::Structure,
            _ => Self::Other,
        }
    }
}

struct ConfigMigration {
    section: MigrationSection,
    output: String,
}

impl ConfigMigration {
    fn new(source_length: usize) -> Self {
        Self {
            section: MigrationSection::Root,
            output: String::with_capacity(source_length),
        }
    }

    fn transition_line(&mut self, raw_line: &str) {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            self.transition_section(raw_line, &trimmed[1..trimmed.len() - 1]);
            return;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            self.copy_line(raw_line);
            return;
        }
        let Some((key, value)) = Self::assignment(trimmed) else {
            self.copy_line(raw_line);
            return;
        };
        self.transition_assignment(raw_line, key, value);
    }

    fn transition_section(&mut self, raw_line: &str, header: &str) {
        self.section = MigrationSection::from_header(header);
        if header != "severity" {
            self.copy_line(raw_line);
            return;
        }
        let header_start = raw_line.len() - raw_line.trim_start().len();
        let header_end = header_start + "[severity]".len();
        self.output.push_str(&raw_line[..header_start]);
        self.output.push_str("[rules.severity]");
        self.output.push_str(&raw_line[header_end..]);
        self.output.push('\n');
    }

    fn assignment(trimmed: &str) -> Option<(&str, &str)> {
        let separator = trimmed.find('=')?;
        let key = trimmed[..separator].trim();
        let value = trimmed[separator + 1..].trim();
        Some((key, value))
    }

    fn transition_assignment(&mut self, raw_line: &str, key: &str, value: &str) {
        let indent_length = raw_line.len() - raw_line.trim_start().len();
        let (prefix, replacement) = self.transitioned_key(key);
        self.output.push_str(&raw_line[..indent_length]);
        self.output.push_str(prefix);
        self.output.push_str(replacement);
        self.output.push_str(" = ");
        if matches!(key, "lang" | "languages") && !value.starts_with('[') {
            self.output.push('[');
            self.output.push_str(value);
            self.output.push(']');
        } else {
            self.output.push_str(value);
        }
        self.output.push('\n');
    }

    fn transitioned_key<'a>(&self, key: &'a str) -> (&'static str, &'a str) {
        match self.section {
            MigrationSection::Root => match key {
                "lang" | "languages" => ("", "languages"),
                "complexity_threshold" => ("analysis.", "complexity_threshold"),
                "cognitive_threshold" => ("analysis.", "cognitive_complexity_threshold"),
                "min_duplication_lines" => ("analysis.", "duplication_min_lines"),
                "max_file_lines" | "max_function_lines" | "csharp_dead_code" => ("analysis.", key),
                "entry_points" => ("files.", "entry_points"),
                "ignore_patterns" => ("files.", "ignore"),
                "include" | "exclude" => ("files.", key),
                "rule_groups" => ("rules.", "enabled_groups"),
                "pattern_rules" => ("rules.", "patterns"),
                _ => ("", key),
            },
            MigrationSection::Structure => match key {
                "max_top_level_files" => ("", "max_root_files"),
                "allowed_top_level" => ("", "allowed_root_files"),
                "required_dirs" => ("", "required_directories"),
                _ => ("", key),
            },
            MigrationSection::Other => ("", key),
        }
    }

    fn copy_line(&mut self, raw_line: &str) {
        self.output.push_str(raw_line);
        self.output.push('\n');
    }

    fn finish(mut self, had_newline: bool) -> String {
        if !had_newline {
            self.output.pop();
        }
        self.output
    }
}

pub fn migrate(source: &str) -> String {
    let mut migration = ConfigMigration::new(source.len());
    for line in source.lines() {
        migration.transition_line(line);
    }
    migration.finish(source.ends_with('\n'))
}

pub fn ordered_rule_groups(groups: &BTreeSet<String>) -> Vec<String> {
    const PREFERRED: &[&str] = &[
        "core",
        "dart-style",
        "yagni",
        "design",
        "security",
        "style",
        "nim-style",
        "nim-advanced",
        "game-engine",
        "architecture",
        "zerocost",
        "idiomatic",
        "suspicious",
        "strings",
        "sql",
        "regex",
    ];
    let mut ordered: Vec<String> = PREFERRED
        .iter()
        .filter(|group| groups.contains(**group))
        .map(|group| (*group).to_owned())
        .collect();
    ordered.extend(
        groups
            .iter()
            .filter(|group| !PREFERRED.contains(&group.as_str()))
            .cloned(),
    );
    ordered
}

fn table<'a>(parent: Option<&'a Table>, key: &str) -> Result<Option<&'a Table>, String> {
    match parent.and_then(|values| values.get(key)) {
        Some(Value::Table(value)) => Ok(Some(value)),
        Some(_) => Err(format!("Invalid code-buster.toml table: {key}")),
        None => Ok(None),
    }
}

fn string(parent: Option<&Table>, key: &str) -> Result<Option<String>, String> {
    match parent.and_then(|values| values.get(key)) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("Invalid code-buster.toml string: {key}")),
        None => Ok(None),
    }
}

fn value_string<'a>(parent: Option<&'a Table>, key: &str) -> Option<&'a str> {
    parent
        .and_then(|values| values.get(key))
        .and_then(Value::as_str)
}

fn string_list(parent: Option<&Table>, key: &str) -> Result<Vec<String>, String> {
    match parent.and_then(|values| values.get(key)) {
        Some(Value::Array(values)) if values.iter().all(|value| value.as_str().is_some()) => {
            Ok(values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect())
        }
        Some(_) => Err(format!("Invalid code-buster.toml string list: {key}")),
        None => Ok(Vec::new()),
    }
}

fn preferred_string_list(
    preferred_parent: Option<&Table>,
    preferred_key: &str,
    legacy_parent: Option<&Table>,
    legacy_key: &str,
) -> Result<Vec<String>, String> {
    if preferred_parent.is_some_and(|values| values.contains_key(preferred_key)) {
        string_list(preferred_parent, preferred_key)
    } else {
        string_list(legacy_parent, legacy_key)
    }
}

fn integer(parent: Option<&Table>, key: &str, fallback: i64) -> Result<i64, String> {
    match parent.and_then(|values| values.get(key)) {
        Some(Value::Integer(value)) => Ok(*value),
        Some(_) => Err(format!("Invalid code-buster.toml integer: {key}")),
        None => Ok(fallback),
    }
}

fn preferred_integer(
    preferred_parent: Option<&Table>,
    preferred_key: &str,
    legacy_parent: Option<&Table>,
    legacy_key: &str,
    fallback: i64,
) -> Result<i64, String> {
    if preferred_parent.is_some_and(|values| values.contains_key(preferred_key)) {
        integer(preferred_parent, preferred_key, fallback)
    } else {
        integer(legacy_parent, legacy_key, fallback)
    }
}

fn boolean(parent: Option<&Table>, key: &str, fallback: bool) -> Result<bool, String> {
    match parent.and_then(|values| values.get(key)) {
        Some(Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(format!("Invalid code-buster.toml boolean: {key}")),
        None => Ok(fallback),
    }
}

fn preferred_boolean(
    preferred_parent: Option<&Table>,
    preferred_key: &str,
    legacy_parent: Option<&Table>,
    legacy_key: &str,
    fallback: bool,
) -> Result<bool, String> {
    if preferred_parent.is_some_and(|values| values.contains_key(preferred_key)) {
        boolean(preferred_parent, preferred_key, fallback)
    } else {
        boolean(legacy_parent, legacy_key, fallback)
    }
}

fn rule_modes(
    values: Option<&Table>,
    validate_semantic_group: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut modes = BTreeMap::new();
    for (name, value) in values.into_iter().flatten() {
        if validate_semantic_group && !SEMANTIC_GROUPS.contains(&name.as_str()) {
            return Err(format!("Unknown Code Buster semantic rule group: {name}"));
        }
        let Some(mode) = value.as_str() else {
            let scope = if validate_semantic_group {
                "group"
            } else {
                "rule"
            };
            return Err(format!("Invalid code-buster.toml {scope} mode for {name}"));
        };
        if !["report", "count", "off"].contains(&mode.to_ascii_lowercase().as_str()) {
            return Err(format!("Unknown Code Buster rule mode: {mode}"));
        }
        modes.insert(name.clone(), mode.to_ascii_lowercase());
    }
    Ok(modes)
}

fn severity_settings(values: Option<&Table>) -> Result<SeveritySettings, String> {
    let mut disabled_rules = BTreeSet::new();
    let mut overrides = BTreeMap::new();
    let mut order = Vec::new();
    for (rule, value) in values.into_iter().flatten() {
        let Some(severity) = value.as_str() else {
            return Err(format!("Invalid code-buster.toml severity for {rule}"));
        };
        let normalized = severity.to_ascii_lowercase();
        if normalized == "off" {
            disabled_rules.insert(rule.clone());
        } else if ["info", "warn", "warning", "error"].contains(&normalized.as_str()) {
            let normalized = if normalized == "warning" {
                "warn".to_owned()
            } else {
                normalized
            };
            overrides.insert(rule.clone(), normalized.clone());
            order.push((rule.clone(), normalized));
        } else {
            return Err(format!("Unknown Code Buster severity: {severity}"));
        }
    }
    Ok(SeveritySettings {
        disabled_rules,
        overrides,
        order,
    })
}

fn semantic_groups_for_legacy(group: &str) -> &'static [&'static str] {
    match group {
        "core" => &["correctness", "maintainability"],
        "style" | "dart-style" | "nim-style" | "idiomatic" | "strings" | "zerocost" => &["style"],
        "security" => &["security"],
        "reliability" => &["reliability"],
        "game-engine" => &["domain"],
        "regex" | "sql" | "suspicious" => &["suspicious"],
        "design" | "yagni" | "nim-advanced" => &["maintainability"],
        value if SEMANTIC_GROUPS.contains(&value) => match value {
            "correctness" => &["correctness"],
            "accessibility" => &["accessibility"],
            "performance" => &["performance"],
            "maintainability" => &["maintainability"],
            "suspicious" => &["suspicious"],
            "architecture" => &["architecture"],
            "domain" => &["domain"],
            "experimental" => &["experimental"],
            _ => &[],
        },
        _ => &[],
    }
}

fn parse_pattern_rule(value: &str) -> Result<Option<PatternRule>, String> {
    let fields = split_pattern_fields(value);
    if fields.len() < 4 || fields[0].trim().is_empty() || fields[2].is_empty() {
        return Ok(None);
    }
    let severity = Severity::parse(fields[1].trim())
        .ok_or_else(|| format!("Unknown Code Buster severity: {}", fields[1].trim()))?;
    Ok(Some(PatternRule {
        id: fields[0].trim().to_owned(),
        severity,
        pattern: fields[2].clone(),
        message: fields[3].trim().to_owned(),
        suggestion: fields.get(4).map_or("", String::as_str).trim().to_owned(),
        pattern_not: fields.get(5).map_or("", String::as_str).trim().to_owned(),
        fix: fields.get(6).map_or("", String::as_str).trim().to_owned(),
        category: fields.get(7).map_or("", String::as_str).trim().to_owned(),
    }))
}

fn split_pattern_fields(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            if character != '|' {
                field.push('\\');
            }
            field.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '|' {
            fields.push(std::mem::take(&mut field));
        } else {
            field.push(character);
        }
    }
    if escaped {
        field.push('\\');
    }
    fields.push(field);
    fields
}

fn normalize_legacy_pipe_escapes(source: &str) -> String {
    let characters: Vec<char> = source.chars().collect();
    let mut normalized = String::with_capacity(source.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '\\' {
            normalized.push(characters[index]);
            index += 1;
            continue;
        }
        let start = index;
        while index < characters.len() && characters[index] == '\\' {
            index += 1;
        }
        let slash_count = index - start;
        let count = if index < characters.len() && characters[index] == '|' && slash_count % 2 == 1
        {
            slash_count + 1
        } else {
            slash_count
        };
        normalized.extend(std::iter::repeat_n('\\', count));
    }
    normalized
}

pub fn absolute_root(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path)
        .map_err(|error| format!("failed to resolve root {}: {error}", path.display()))?;
    if !absolute.is_dir() {
        return Err(format!(
            "analysis root does not exist: {}",
            absolute.display()
        ));
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::migrate;

    #[test]
    fn migrate_preserves_non_assignment_lines_and_continues() {
        let source = "not an assignment\nlang = \"rust\"";

        assert_eq!(migrate(source), "not an assignment\nlanguages = [\"rust\"]");
    }
}
