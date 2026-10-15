use std::collections::BTreeMap;

use crate::dependency_graph::DependencyGraph;
use crate::discovery::PreparedPreview;
use crate::findings::Finding;
use crate::function_sources::FunctionSource;
use crate::languages::dart::index::DartSourceIndex;
use crate::source_analysis_context::SourceAnalysisContext;
use crate::yagni_call_index::YagniCallIndex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RulePackPhase {
    Main,
    AfterMain,
}

#[derive(Clone, Copy)]
pub struct RulePack {
    pub id: &'static str,
    pub family: &'static str,
    pub languages: &'static [&'static str],
    pub framework: Option<&'static str>,
    pub phase: RulePackPhase,
    pub needs_functions: bool,
    pub needs_yagni_index: bool,
    pub analyze: for<'call, 'source, 'functions> fn(
        &RulePackContext<'call, 'source, 'functions>,
    ) -> Result<RulePackOutput, String>,
}

impl RulePack {
    pub const fn main(
        id: &'static str,
        family: &'static str,
        languages: &'static [&'static str],
        framework: Option<&'static str>,
        needs_functions: bool,
        needs_yagni_index: bool,
        analyze: for<'call, 'source, 'functions> fn(
            &RulePackContext<'call, 'source, 'functions>,
        ) -> Result<RulePackOutput, String>,
    ) -> Self {
        Self {
            id,
            family,
            languages,
            framework,
            phase: RulePackPhase::Main,
            needs_functions,
            needs_yagni_index,
            analyze,
        }
    }

    pub const fn after_main(
        id: &'static str,
        family: &'static str,
        needs_functions: bool,
        needs_yagni_index: bool,
        analyze: for<'call, 'source, 'functions> fn(
            &RulePackContext<'call, 'source, 'functions>,
        ) -> Result<RulePackOutput, String>,
    ) -> Self {
        Self {
            id,
            family,
            languages: &[],
            framework: None,
            phase: RulePackPhase::AfterMain,
            needs_functions,
            needs_yagni_index,
            analyze,
        }
    }
}

pub struct RulePackContext<'call, 'source, 'functions> {
    pub prepared: &'call PreparedPreview,
    pub source_context: &'source SourceAnalysisContext<'source>,
    pub graph: &'call DependencyGraph,
    pub functions: &'functions [FunctionSource],
    pub dart_index: Option<&'call DartSourceIndex<'source>>,
    pub yagni_index: Option<&'call YagniCallIndex<'functions>>,
    pub prior_findings: &'call [Finding],
    pub collect_timings: bool,
}

#[derive(Default)]
pub struct RulePackOutput {
    pub findings: Vec<Finding>,
    pub shared_durations_microseconds: BTreeMap<String, u128>,
    pub rule_durations_microseconds: BTreeMap<String, u128>,
}

impl RulePackOutput {
    pub fn findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            shared_durations_microseconds: BTreeMap::new(),
            rule_durations_microseconds: BTreeMap::new(),
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/rule_packs.rs"));

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{RULE_PACK_SOURCES, RULE_PACKS, RulePackPhase};
    use crate::rule_catalog::RULE_METADATA;

    #[test]
    fn registry_has_unique_ids_and_post_processing_packs_are_last() {
        assert!(!RULE_PACKS.is_empty());
        assert_eq!(RULE_PACKS.len(), RULE_PACK_SOURCES.len());
        let mut ids = BTreeSet::new();
        let mut reached_after_main = false;

        for (pack, source) in RULE_PACKS.iter().zip(RULE_PACK_SOURCES) {
            assert!(!pack.id.is_empty());
            assert!(!pack.family.is_empty());
            assert!(ids.insert(pack.id), "duplicate rule-pack ID {}", pack.id);
            let (_, source_id) = source
                .split_once('-')
                .expect("validated pack filenames contain an order separator");
            assert_eq!(source_id, pack.id, "pack ID must match its filename");
            match pack.phase {
                RulePackPhase::Main => assert!(
                    !reached_after_main,
                    "main rule pack {} follows an after-main pack",
                    pack.id
                ),
                RulePackPhase::AfterMain => reached_after_main = true,
            }
        }
    }

    #[test]
    fn every_metadata_pack_reference_resolves() {
        let families = RULE_PACKS
            .iter()
            .map(|pack| pack.family)
            .collect::<BTreeSet<_>>();

        for metadata in RULE_METADATA {
            assert!(
                !metadata.packs.is_empty(),
                "rule {} has no owning pack",
                metadata.id
            );
            for pack in metadata.packs {
                assert!(
                    families.contains(pack),
                    "rule {} references unknown pack {pack}",
                    metadata.id
                );
            }
        }
    }
}
