use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "ai-security",
    "ai-security",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::ai_security_rules::analyze(context.source_context)))
}
