use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "feature-flags",
    "feature-flags",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::feature_flags::analyze(context.source_context.sources())))
}
