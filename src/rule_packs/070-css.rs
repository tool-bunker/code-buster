use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "css",
    "css",
    &["css"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::css_rules::analyze(context.source_context.sources())))
}
