use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "svelte",
    "svelte",
    &[],
    Some("svelte"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::svelte_rules::analyze(context.source_context.sources())))
}
