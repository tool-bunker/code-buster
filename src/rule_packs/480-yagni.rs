use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "yagni",
    "yagni",
    &[],
    None,
    true,
    true,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let index = context
        .yagni_index
        .ok_or_else(|| "YAGNI index is unavailable".to_owned())?;
    let mut findings = crate::yagni_rules::analyze(index);
    findings.extend(crate::yagni_rules::single_concrete_generics(
        index,
        context.source_context.sources(),
    ));
    Ok(RulePackOutput::findings(findings))
}
