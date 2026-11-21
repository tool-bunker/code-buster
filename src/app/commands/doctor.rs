use crate::discovery::prepare;
use crate::duplication;
use crate::options::PreviewOptions;

pub fn execute(options: &PreviewOptions) -> Result<(), String> {
    let prepared = prepare(options)?;
    let duplicate_count = if duplicate_rule_enabled(options, &prepared.config) {
        duplication::exact_group_count(&prepared.sources, prepared.config.min_duplication_lines)
    } else {
        0
    };

    super::write_report(options, |writer| {
        writeln!(writer, "Code Buster doctor")?;
        writeln!(
            writer,
            "- Hidden directories are skipped by default; use explicit includes only if you want to analyze hidden tooling/vendor folders."
        )?;
        if !prepared.coverage.is_empty() {
            let coverage = prepared
                .coverage
                .iter()
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(writer, "- Coverage: {coverage}")?;
        }
        if duplicate_count > 20 {
            writeln!(
                writer,
                "- There are many duplicate-block findings; consider raising min_duplication_lines above {}.",
                prepared.config.min_duplication_lines
            )?;
        }
        if prepared.files.is_empty() {
            writeln!(
                writer,
                "- No source files were discovered; check --root, --lang, and ignore_patterns."
            )?;
        }
        Ok(())
    })
}

fn duplicate_rule_enabled(options: &PreviewOptions, config: &crate::config::Config) -> bool {
    options.only == "duplicate-block"
        && !config.disabled_rules.contains("duplicate-block")
        && config
            .rule_modes
            .get("duplicate-block")
            .is_none_or(|mode| mode != "off")
        && config
            .group_modes
            .get("maintainability")
            .is_none_or(|mode| mode != "off")
}
