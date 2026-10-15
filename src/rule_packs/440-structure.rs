use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "structure",
    "structure",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::structure::analyze(&context.prepared.files, &context.prepared.config)))
}
