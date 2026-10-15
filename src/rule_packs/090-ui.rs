use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "ui",
    "ui",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::ui_consistency::analyze(context.source_context)))
}
