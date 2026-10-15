use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "advanced-duplication",
    "advanced-duplication",
    &[],
    None,
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let mode = context.prepared.config.duplication_mode.as_str();
    if mode == "exact" {
        return Ok(RulePackOutput::default());
    }
    let mut findings = crate::advanced_duplication::near_duplicate_functions(context.functions);
    if mode == "semantic" {
        findings.extend(crate::advanced_duplication::parallel_contract_implementations(
            context.functions,
        ));
    }
    Ok(RulePackOutput::findings(findings))
}
