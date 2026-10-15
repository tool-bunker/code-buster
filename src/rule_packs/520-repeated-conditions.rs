use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "repeated-conditions",
    "duplication",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::duplication::repeated_condition_findings(context.source_context.sources()),
    ))
}
