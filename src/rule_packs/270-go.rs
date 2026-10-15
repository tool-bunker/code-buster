use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "go",
    "go",
    &["go"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::go_rules::analyze(context.source_context.sources())))
}
