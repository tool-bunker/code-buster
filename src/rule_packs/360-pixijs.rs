use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "pixijs",
    "pixijs",
    &[],
    Some("pixijs"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::pixijs_rules::analyze(context.source_context)))
}
