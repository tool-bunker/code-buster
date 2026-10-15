use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "trivial-wrappers",
    "trivial-wrappers",
    &[],
    None,
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::trivial_wrappers::analyze(context.functions)))
}
