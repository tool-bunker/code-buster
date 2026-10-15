use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "fastapi",
    "fastapi",
    &[],
    Some("fastapi"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::fastapi_rules::analyze(context.source_context)))
}
