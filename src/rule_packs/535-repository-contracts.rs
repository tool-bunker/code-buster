use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "repository-contracts",
    "repository-contracts",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::repository_contract_rules::analyze(
            context.prepared,
            context.source_context,
            context.graph,
        ),
    ))
}
