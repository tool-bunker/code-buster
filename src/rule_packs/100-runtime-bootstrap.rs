use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "runtime-bootstrap",
    "runtime-bootstrap",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::runtime_bootstrap_rule::analyze(context.source_context)))
}
