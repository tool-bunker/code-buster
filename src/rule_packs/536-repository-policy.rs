use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "repository-policy",
    "repository-policy",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::repository_policy_rules::analyze(context.source_context),
    ))
}
