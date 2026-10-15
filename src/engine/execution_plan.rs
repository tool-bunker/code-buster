use std::collections::BTreeSet;

use crate::cli::PreviewOptions;
use crate::config::Config;
use crate::finding_controls;
use crate::rule_catalog;

pub struct ExecutionPlan<'a> {
    languages: BTreeSet<&'a str>,
    only_families: Option<&'static [&'static str]>,
    selected_rule_active: bool,
}

impl<'a> ExecutionPlan<'a> {
    pub fn new(
        options: &PreviewOptions,
        config: &Config,
        languages: impl Iterator<Item = &'a str>,
    ) -> Self {
        let only_families = if options.only.is_empty() {
            None
        } else {
            packs_for_rule(&options.only)
        };
        let selected_rule_active =
            options.only.is_empty() || rule_active(&options.only, config, &options.finding_group);
        Self {
            languages: languages.collect(),
            only_families,
            selected_rule_active,
        }
    }

    pub fn allows(&self, family: &str) -> bool {
        self.selected_rule_active
            && self
                .only_families
                .is_none_or(|families| families.contains(&family))
    }

    pub fn selects_language(&self, language: &str) -> bool {
        self.languages.contains(language)
    }
}

fn rule_active(code: &str, config: &Config, requested_group: &str) -> bool {
    if config.disabled_rules.contains(code) {
        return false;
    }
    let group = rule_catalog::descriptor(code).map_or("security", |descriptor| descriptor.group);
    (requested_group.is_empty() || requested_group == group)
        && finding_controls::mode_for_code(code, config, group) != "off"
}

fn packs_for_rule(code: &str) -> Option<&'static [&'static str]> {
    rule_catalog::metadata(code).map(|metadata| metadata.packs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_pack_routing_from_canonical_rule_metadata() {
        assert_eq!(
            packs_for_rule("oop-feature-envy"),
            Some(&["dart-oop", "oop", "csharp", "typescript"][..])
        );
        assert_eq!(
            packs_for_rule("dart-null-assertion"),
            Some(&["dart-null-assertion"][..])
        );
        assert_eq!(packs_for_rule("tab-indent"), Some(&["layout"][..]));
    }
}
