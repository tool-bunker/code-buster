use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "complexity",
    "complexity",
    &[],
    None,
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::complexity::analyze(context.functions, context.source_context.sources(), &context.prepared.config)))
}
