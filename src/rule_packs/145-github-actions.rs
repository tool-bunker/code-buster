use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "github-actions",
    "github-actions",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::github_actions_rules::analyze(context.source_context),
    ))
}
