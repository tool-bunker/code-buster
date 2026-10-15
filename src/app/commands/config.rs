use std::collections::BTreeMap;
use std::fs;

use serde_json::{Map, Value, json};

use crate::cli::{ConfigOptions, ReportFormat};
use crate::config::{Config, absolute_root, migrate, ordered_rule_groups, validate};
use crate::languages;
use crate::repository_defaults::RepositoryDefaults;

pub fn execute(options: &ConfigOptions) -> Result<(), String> {
    let root = absolute_root(&options.root)?;
    let path = root.join("code-buster.toml");
    match options.target.as_deref() {
        Some("validate") => validate_file(&path),
        Some("explain") => explain(&root, &path, options),
        Some("migrate") => migrate_file(&path, options.dry_run),
        _ => show(&root, options),
    }
}

fn validate_file(path: &std::path::Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!(
            "error: configuration not found: {}",
            path.display()
        ));
    }
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let diagnostics = validate(&source);
    if diagnostics.is_empty() {
        println!("Code Buster configuration is valid");
        return Ok(());
    }
    Err(diagnostics
        .into_iter()
        .map(|diagnostic| format!("error: {diagnostic}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn migrate_file(path: &std::path::Path, dry_run: bool) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("configuration not found: {}", path.display()));
    }
    let original = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let migrated = migrate(&original);
    if migrated == original {
        println!("Code Buster configuration is already current");
    } else if dry_run {
        print!("{migrated}");
    } else {
        let backup = path.with_file_name("code-buster.toml.bak");
        fs::write(&backup, original)
            .map_err(|error| format!("failed to write {}: {error}", backup.display()))?;
        fs::write(path, migrated)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
        println!("migrated {}", path.display());
        println!("backup: {}", backup.display());
    }
    Ok(())
}

fn show(root: &std::path::Path, options: &ConfigOptions) -> Result<(), String> {
    let mut config = Config::load_from_root(root.to_path_buf())?;
    if let Some(language) = &options.language {
        config.language.clone_from(language);
    }
    if !options.languages.is_empty() {
        config.languages.clone_from(&options.languages);
    }
    config.changed_lines = options.changed_lines;

    if options.format == ReportFormat::Json {
        let mut report = Map::new();
        report.insert("root".to_owned(), json!(root));
        report.insert(
            "config_file".to_owned(),
            json!(root.join("code-buster.toml")),
        );
        report.insert("languages".to_owned(), json!(effective_languages(&config)));
        report.insert(
            "min_duplication_lines".to_owned(),
            json!(config.min_duplication_lines),
        );
        report.insert(
            "duplication_mode".to_owned(),
            json!(config.duplication_mode),
        );
        report.insert("quality_profile".to_owned(), json!(config.quality_profile));
        report.insert("quality_gates".to_owned(), json!(config.quality_gates));
        report.insert(
            "complexity_threshold".to_owned(),
            json!(config.complexity_threshold),
        );
        report.insert(
            "cognitive_threshold".to_owned(),
            json!(config.cognitive_threshold),
        );
        report.insert("max_file_lines".to_owned(), json!(config.max_file_lines));
        report.insert("ignore_patterns".to_owned(), json!(config.ignore_patterns));
        report.insert("entry_points".to_owned(), json!(config.entry_points));
        report.insert(
            "pattern_rules".to_owned(),
            json!(config.pattern_rules.len()),
        );
        report.insert(
            "rule_groups".to_owned(),
            json!(ordered_rule_groups(&config.rule_groups)),
        );
        report.insert("group_modes".to_owned(), json!(config.group_modes));
        report.insert("rule_modes".to_owned(), json!(config.rule_modes));
        report.insert("severity_off".to_owned(), json!(config.disabled_rules));
        report.insert("include".to_owned(), json!(config.includes));
        report.insert("exclude".to_owned(), json!(config.excludes));
        report.insert("only".to_owned(), json!(options.only));
        report.insert(
            "changed_base".to_owned(),
            json!(config.changed_base.as_deref().unwrap_or("")),
        );
        report.insert("changed_lines".to_owned(), json!(config.changed_lines));
        report.insert(
            "structure_source_roots".to_owned(),
            json!(config.structure_source_roots),
        );
        report.insert(
            "structure_max_top_level_files".to_owned(),
            json!(config.structure_max_top_level_files),
        );
        report.insert(
            "structure_allowed_top_level".to_owned(),
            json!(config.structure_allowed_top_level),
        );
        report.insert(
            "structure_required_dirs".to_owned(),
            json!(config.structure_required_directories),
        );
        report.insert(
            "architecture_layers".to_owned(),
            json!(config.architecture_layers),
        );
        report.insert(
            "architecture_allowed_dependencies".to_owned(),
            json!(config.architecture_allowed_dependencies),
        );
        report.insert(
            "architecture_denied_dependencies".to_owned(),
            json!(config.architecture_denied_dependencies),
        );
        if config.dart_mvvm_enabled() {
            report.insert(
                "architecture_profile".to_owned(),
                json!(config.architecture_profile),
            );
            report.insert("mvvm_views".to_owned(), json!(config.mvvm_views));
            report.insert(
                "mvvm_view_models".to_owned(),
                json!(config.mvvm_view_models),
            );
            report.insert("mvvm_models".to_owned(), json!(config.mvvm_models));
            report.insert(
                "mvvm_repositories".to_owned(),
                json!(config.mvvm_repositories),
            );
            report.insert(
                "mvvm_strict_view_model_boundary".to_owned(),
                json!(config.mvvm_strict_view_model_boundary),
            );
        }
        println!("{}", Value::Object(report));
    } else {
        println!("root={}", root.display());
        println!("lang={}", config.language);
        println!("min_duplication_lines={}", config.min_duplication_lines);
        println!("duplication_mode={}", config.duplication_mode);
        println!("quality_profile={}", config.quality_profile);
        println!("quality_gates={}", config.quality_gates.join(","));
        println!("complexity_threshold={}", config.complexity_threshold);
        println!("cognitive_threshold={}", config.cognitive_threshold);
        println!("max_file_lines={}", config.max_file_lines);
        println!("ignore_patterns={}", config.ignore_patterns.join(","));
        println!("entry_points={}", config.entry_points.join(","));
        for (group, mode) in &config.group_modes {
            println!("rules.groups.{group}={mode}");
        }
        for (rule, mode) in &config.rule_modes {
            println!("rules.mode.{rule}={mode}");
        }
    }
    Ok(())
}

const EXPLAIN_PRECEDENCE: [&str; 5] = [
    "code-buster defaults",
    "language/framework detection",
    "repository formatter files",
    "code-buster.toml",
    "CLI overrides",
];

struct ExplainSelection<'a> {
    config_path: Option<&'a std::path::Path>,
    scope: String,
    defaults: RepositoryDefaults,
    effective: Config,
    formatter_files: Vec<&'static str>,
    language_versions: Vec<(String, String)>,
    include_all: bool,
}

impl ExplainSelection<'_> {
    fn setting_source(&self) -> &'static str {
        if self.config_path.is_some() {
            "built-in defaults with code-buster.toml overrides"
        } else {
            "built-in language/framework defaults"
        }
    }

    fn production_ignores(&self) -> &[String] {
        if self.include_all {
            &[]
        } else {
            &self.defaults.ignores
        }
    }
}

fn explain(
    root: &std::path::Path,
    path: &std::path::Path,
    options: &ConfigOptions,
) -> Result<(), String> {
    let selection = select_explanation(root, path, options)?;
    if options.format == ReportFormat::Json {
        render_explanation_json(&selection);
    } else {
        render_explanation_text(&selection);
    }
    Ok(())
}

fn select_explanation<'a>(
    root: &std::path::Path,
    path: &'a std::path::Path,
    options: &ConfigOptions,
) -> Result<ExplainSelection<'a>, String> {
    let defaults = RepositoryDefaults::infer(
        root,
        options.include_all || options.include_tests,
        options.include_all || options.include_examples,
        options.include_all || options.include_vendored,
    );
    let config_path = path.is_file().then_some(path);
    let mut effective = Config::load_from_root(root.to_path_buf())?;
    effective.frameworks.clone_from(&defaults.frameworks);
    let formatter_files = [
        ".editorconfig",
        ".prettierrc",
        ".prettierrc.json",
        "biome.json",
    ]
    .into_iter()
    .filter(|name| root.join(name).is_file())
    .collect();
    let language_versions = languages::detect_versions_ordered(root);
    let scope = selected_scope(options);

    Ok(ExplainSelection {
        config_path,
        scope,
        defaults,
        effective,
        formatter_files,
        language_versions,
        include_all: options.include_all,
    })
}

fn selected_scope(options: &ConfigOptions) -> String {
    if options.include_all {
        return "all".to_owned();
    }
    let mut scopes = vec!["production"];
    if options.include_tests {
        scopes.push("tests");
    }
    if options.include_examples {
        scopes.push("examples");
    }
    if options.include_vendored {
        scopes.push("vendored");
    }
    scopes.join("+")
}

fn render_explanation_json(selection: &ExplainSelection<'_>) {
    let effective = &selection.effective;
    let effective_report = json!({
        "languages": effective_languages(effective),
        "frameworks": effective.frameworks,
        "duplication_min_lines": effective.min_duplication_lines,
        "duplication_mode": effective.duplication_mode,
        "quality_profile": effective.quality_profile,
        "quality_gates": effective.quality_gates,
        "complexity_threshold": effective.complexity_threshold,
        "cognitive_threshold": effective.cognitive_threshold,
        "rule_groups": ordered_rule_groups(&effective.rule_groups),
        "group_modes": effective.group_modes,
        "rule_modes": effective.rule_modes,
        "classification.production": effective.classification_production,
        "classification.test": effective.classification_test,
        "classification.generated": effective.classification_generated,
    });
    println!(
        "{}",
        json!({
            "config_file": selection.config_path
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
            "scope": selection.scope,
            "detected_profiles": selection.defaults.profiles,
            "detected_frameworks": selection.defaults.frameworks,
            "language_versions": selection.language_versions.iter().cloned().collect::<BTreeMap<_, _>>(),
            "formatter_files": selection.formatter_files,
            "effective": effective_report,
            "setting_source": selection.setting_source(),
            "production_ignores": selection.production_ignores(),
            "precedence": EXPLAIN_PRECEDENCE,
        })
    );
}

fn render_explanation_text(selection: &ExplainSelection<'_>) {
    match selection.config_path {
        Some(path) => println!("config_file={}", path.display()),
        None => println!("config_file=none"),
    }
    println!("scope={}", selection.scope);
    println!(
        "detected_profiles={}",
        display_list(selection.defaults.profiles.iter().map(String::as_str))
    );
    println!(
        "detected_frameworks={}",
        display_list(selection.defaults.frameworks.iter().map(String::as_str))
    );
    println!(
        "language_versions={}",
        display_language_versions(&selection.language_versions)
    );
    println!(
        "formatter_files={}",
        display_list(selection.formatter_files.iter().copied())
    );
    println!("setting_source={}", selection.setting_source());
    render_effective_text(&selection.effective);
    println!(
        "production_ignores={}",
        selection.production_ignores().join(",")
    );
    println!("precedence={}", EXPLAIN_PRECEDENCE.join(" -> "));
}

fn render_effective_text(effective: &Config) {
    println!(
        "languages={}",
        dart_display(&json!(effective_languages(effective)))
    );
    println!("frameworks={}", dart_display(&json!(effective.frameworks)));
    println!("duplication_min_lines={}", effective.min_duplication_lines);
    println!("duplication_mode={}", effective.duplication_mode);
    println!("quality_profile={}", effective.quality_profile);
    println!(
        "quality_gates={}",
        dart_display(&json!(effective.quality_gates))
    );
    println!("complexity_threshold={}", effective.complexity_threshold);
    println!("cognitive_threshold={}", effective.cognitive_threshold);
    println!(
        "rule_groups={}",
        dart_display(&json!(ordered_rule_groups(&effective.rule_groups)))
    );
    println!(
        "group_modes={}",
        dart_display(&json!(effective.group_modes))
    );
    println!("rule_modes={}", dart_display(&json!(effective.rule_modes)));
    println!(
        "classification.production={}",
        dart_display(&json!(effective.classification_production))
    );
    println!(
        "classification.test={}",
        dart_display(&json!(effective.classification_test))
    );
    println!(
        "classification.generated={}",
        dart_display(&json!(effective.classification_generated))
    );
}

fn display_language_versions(versions: &[(String, String)]) -> String {
    let mut versions = versions.iter();
    let Some((language, version)) = versions.next() else {
        return "none".to_owned();
    };
    let mut display = format!("{language}:{version}");
    for (language, version) in versions {
        display.push(',');
        display.push_str(language);
        display.push(':');
        display.push_str(version);
    }
    display
}

fn effective_languages(config: &Config) -> Vec<String> {
    if config.languages.is_empty() {
        vec![config.language.clone()]
    } else {
        config.languages.clone()
    }
}

fn display_list<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return "none".to_owned();
    };
    let mut display = first.to_owned();
    for value in values {
        display.push(',');
        display.push_str(value);
    }
    display
}

fn dart_display(value: &Value) -> String {
    match value {
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(dart_display)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{key}: {}", dart_display(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}
