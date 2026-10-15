use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "wren",
    "wren",
    &["wren"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::wren_rules::analyze(context.source_context)))
}
