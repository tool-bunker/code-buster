use std::collections::BTreeSet;

use serde::Serialize;

use crate::cli::{PreviewOptions, ReportFormat};
use crate::config::{Config, absolute_root};
use crate::rule_catalog::{RULE_DESCRIPTORS, RuleDescriptor};

#[derive(Serialize)]
struct RulesReport<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    command: &'static str,
    rules: &'a [RenderedRule],
}

#[derive(Serialize)]
struct RenderedRule {
    id: &'static str,
    language: &'static str,
    group: &'static str,
    mode: &'static str,
    title: &'static str,
    #[serde(rename = "inactiveReason", skip_serializing_if = "Option::is_none")]
    inactive_reason: Option<&'static str>,
}

pub fn execute(options: &PreviewOptions) -> Result<(), String> {
    let root = absolute_root(&options.root)?;
    let config = Config::load_from_root(root)?;
    let rules = select_catalog_rules(&config, options.inactive_rules);

    match &options.format {
        ReportFormat::Json => print_json(&rules),
        _ => {
            print_text(&rules);
            Ok(())
        }
    }
}

fn select_catalog_rules(config: &Config, inactive_only: bool) -> Vec<RenderedRule> {
    let languages = configured_languages(config);
    RULE_DESCRIPTORS
        .iter()
        .filter(|descriptor| catalog_includes(descriptor, config, &languages))
        .filter_map(|descriptor| {
            let mode = mode_for(descriptor, config);
            if inactive_only && mode != "off" {
                return None;
            }
            Some(render_rule(descriptor, config, mode))
        })
        .collect()
}

fn configured_languages(config: &Config) -> BTreeSet<&str> {
    if config.languages.is_empty() {
        BTreeSet::from([config.language.as_str()])
    } else {
        config.languages.iter().map(String::as_str).collect()
    }
}

fn catalog_includes(
    descriptor: &RuleDescriptor,
    config: &Config,
    languages: &BTreeSet<&str>,
) -> bool {
    if descriptor.mvvm && !config.dart_mvvm_enabled() {
        return false;
    }
    languages.contains("auto")
        || descriptor.language == "all"
        || languages.contains(descriptor.language)
}

fn render_rule(descriptor: &RuleDescriptor, config: &Config, mode: &'static str) -> RenderedRule {
    RenderedRule {
        id: descriptor.id,
        language: descriptor.language,
        group: descriptor.group,
        mode,
        title: descriptor.title,
        inactive_reason: inactive_reason(descriptor, config, mode),
    }
}

fn inactive_reason(
    descriptor: &RuleDescriptor,
    config: &Config,
    mode: &'static str,
) -> Option<&'static str> {
    if mode != "off" {
        return None;
    }
    Some(if config.disabled_rules.contains(descriptor.id) {
        "explicitly disabled"
    } else if descriptor.group == "architecture" {
        "requires architecture configuration"
    } else if descriptor.group == "domain" {
        "requires a detected or configured domain profile"
    } else {
        "disabled by group or rule mode"
    })
}

fn print_json(rules: &[RenderedRule]) -> Result<(), String> {
    let output = serde_json::to_string(&RulesReport {
        schema_version: 3,
        command: "rules",
        rules,
    })
    .map_err(|error| format!("failed to encode rules report: {error}"))?;
    println!("{output}");
    Ok(())
}

fn print_text(rules: &[RenderedRule]) {
    println!("Code Buster rules");
    for rule in rules {
        let reason = rule
            .inactive_reason
            .map_or_else(String::new, |reason| format!(" ({reason})"));
        println!(
            "{:<7} {} [{}/{}] — {}{}",
            rule.mode, rule.id, rule.language, rule.group, rule.title, reason
        );
    }
}

fn mode_for(descriptor: &RuleDescriptor, config: &Config) -> &'static str {
    if config.disabled_rules.contains(descriptor.id) {
        return "off";
    }
    if let Some(mode) = config.rule_modes.get(descriptor.id) {
        return stable_mode(mode);
    }
    if config.severity_overrides.contains_key(descriptor.id) {
        return "report";
    }
    if let Some(mode) = config.group_modes.get(descriptor.group) {
        return stable_mode(mode);
    }
    if matches!(
        descriptor.id,
        "flutter-gesture-semantic-gap" | "flutter-listener-without-remove"
    ) {
        return "count";
    }
    if descriptor.id.starts_with("dart-")
        && matches!(descriptor.group, "correctness" | "reliability")
        && descriptor.id != "dart-unreachable-statement"
    {
        return "count";
    }
    default_mode(descriptor.group)
}

fn stable_mode(mode: &str) -> &'static str {
    match mode {
        "off" => "off",
        "report" => "report",
        _ => "count",
    }
}

fn default_mode(group: &str) -> &'static str {
    match group {
        "core" | "correctness" | "security" | "reliability" | "accessibility" => "report",
        "architecture" | "game-engine" | "domain" | "experimental" => "off",
        _ => "count",
    }
}
