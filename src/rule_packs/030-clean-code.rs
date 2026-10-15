use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "clean-code",
    "clean-code",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::clean_code_rules::analyze(context.source_context)))
}
