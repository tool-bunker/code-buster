use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "bevy",
    "bevy",
    &["rust"],
    Some("bevy"),
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::bevy_rules::analyze(
        context.source_context,
        context.functions,
    )))
}
