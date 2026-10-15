use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "python",
    "python",
    &["python"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::python_rules::analyze(context.source_context)))
}
