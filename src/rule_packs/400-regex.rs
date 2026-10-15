use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "regex",
    "regex",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::regex_rules::analyze(context.source_context.sources())))
}
