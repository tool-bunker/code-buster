use crate::cli::RepositoryViewOptions;
use crate::repository_view_command::RepositoryViewOutcome;
use crate::rule_catalog;

pub fn execute(options: &RepositoryViewOptions) -> Result<RepositoryViewOutcome, String> {
    let Some(code) = options.targets.first().filter(|code| !code.is_empty()) else {
        eprintln!("rules requires a rule ID");
        return Ok(RepositoryViewOutcome::Usage);
    };
    let Some(rule) = rule_catalog::metadata(code) else {
        eprintln!("unknown or unimplemented rule: {code}");
        return Ok(RepositoryViewOutcome::NotFound);
    };

    super::write_report(&options.common, |writer| {
        writeln!(writer, "{}", rule.id)?;
        writeln!(writer, "Version: {}", rule.version)?;
        writeln!(writer, "Semantic maturity: {}", rule.semantic_maturity)?;
        writeln!(writer, "Security kind: {}", rule.security_kind)?;
        writeln!(writer, "Taxonomy: {}", rule.taxonomy.join(", "))?;
        writeln!(writer, "Requirements: {}", rule.requirements.join(", "))?;
        if rule.languages.is_empty() {
            writeln!(writer, "Languages: descriptor-derived")?;
        } else {
            writeln!(writer, "Languages: {}", rule.languages.join(", "))?;
        }
        if !rule.frameworks.is_empty() {
            writeln!(writer, "Frameworks: {}", rule.frameworks.join(", "))?;
        }
        if !rule.language_versions.is_empty() {
            writeln!(
                writer,
                "Language versions: {}",
                rule.language_versions
                    .iter()
                    .map(|(language, version)| format!("{language} {version}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        if !rule.limitations.is_empty() {
            writeln!(writer, "Limitations: {}", rule.limitations.join("; "))?;
        }
        writeln!(writer)?;
        writeln!(writer, "What it means:")?;
        writeln!(writer, "  {}", rule.why)?;
        writeln!(writer)?;
        writeln!(writer, "Confidence:")?;
        if rule.id == "feature-flag" {
            writeln!(
                writer,
                "  Medium. Some project-specific flag containers may be false positives."
            )?;
        } else {
            writeln!(
                writer,
                "  High. Heuristic finding; review surrounding code and project conventions."
            )?;
        }
        writeln!(writer)?;
        writeln!(writer, "Suggested fixes:")?;
        writeln!(writer, "  {}", rule.suggestion)
    })?;
    Ok(RepositoryViewOutcome::Success)
}
