use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "nim",
    "nim",
    &["nim"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::nim_rules::analyze(context.source_context.sources())))
}
