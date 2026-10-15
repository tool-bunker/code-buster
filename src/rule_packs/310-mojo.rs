use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "mojo",
    "mojo",
    &["mojo"],
    None,
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::mojo_rules::analyze(context.source_context.sources(), context.functions)))
}
