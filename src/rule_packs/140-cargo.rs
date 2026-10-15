use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "cargo",
    "cargo",
    &["rust"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::cargo_rules::analyze(context.source_context)))
}
