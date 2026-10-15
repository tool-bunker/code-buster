use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "generated-code",
    "generated-code",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::generated_code_risks::analyze(context.source_context)))
}
