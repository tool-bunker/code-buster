use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "layout",
    "layout",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::layout_rules::analyze(context.source_context.sources(), &context.prepared.config)))
}
