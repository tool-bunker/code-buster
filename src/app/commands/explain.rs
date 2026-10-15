use crate::cli::RepositoryViewOptions;
use crate::repository_view_command::RepositoryViewOutcome;
use crate::rule_catalog;

pub fn execute(options: &RepositoryViewOptions) -> RepositoryViewOutcome {
    let Some(code) = options.targets.first().filter(|code| !code.is_empty()) else {
        eprintln!("explain requires a rule ID");
        return RepositoryViewOutcome::Usage;
    };
    let Some(rule) = rule_catalog::metadata(code) else {
        eprintln!("unknown or unimplemented rule: {code}");
        return RepositoryViewOutcome::NotFound;
    };

    println!("{}", rule.id);
    println!("Version: {}", rule.version);
    println!("Semantic maturity: {}", rule.semantic_maturity);
    println!("Security kind: {}", rule.security_kind);
    println!("Taxonomy: {}", rule.taxonomy.join(", "));
    println!("Requirements: {}", rule.requirements.join(", "));
    if rule.languages.is_empty() {
        println!("Languages: descriptor-derived");
    } else {
        println!("Languages: {}", rule.languages.join(", "));
    }
    if !rule.frameworks.is_empty() {
        println!("Frameworks: {}", rule.frameworks.join(", "));
    }
    if !rule.language_versions.is_empty() {
        println!(
            "Language versions: {}",
            rule.language_versions
                .iter()
                .map(|(language, version)| format!("{language} {version}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !rule.limitations.is_empty() {
        println!("Limitations: {}", rule.limitations.join("; "));
    }
    println!();
    println!("What it means:");
    println!("  {}", rule.why);
    println!();
    println!("Confidence:");
    if rule.id == "feature-flag" {
        println!("  Medium. Some project-specific flag containers may be false positives.");
    } else {
        println!("  High. Heuristic finding; review surrounding code and project conventions.");
    }
    println!();
    println!("Suggested fixes:");
    println!("  {}", rule.suggestion);
    RepositoryViewOutcome::Success
}
