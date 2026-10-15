use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "dead",
    "dead",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::dead_analysis::analyze(
        context.prepared,
        context.graph,
    )))
}
