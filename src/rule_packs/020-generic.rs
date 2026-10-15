use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "generic",
    "generic",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::generic_rules::analyze(context.source_context.sources(), &context.prepared.config)))
}
