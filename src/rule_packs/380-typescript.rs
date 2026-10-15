use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "typescript",
    "typescript",
    &["javascript", "typescript"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::typescript_rules::analyze(context.source_context)))
}
