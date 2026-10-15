use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "flutter",
    "flutter",
    &[],
    Some("flutter"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::flutter_quality_rules::analyze(context.source_context)))
}
