use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "lua",
    "lua",
    &["lua"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::lua_rules::analyze(context.source_context.sources())))
}
