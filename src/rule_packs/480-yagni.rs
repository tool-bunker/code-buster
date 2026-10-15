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
    Ok(RulePackOutput::findings(crate::yagni_rules::analyze(context.yagni_index.ok_or_else(|| "YAGNI index is unavailable".to_owned())?)))
}
