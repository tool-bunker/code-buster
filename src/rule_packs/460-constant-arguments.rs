use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "constant-arguments",
    "constant-arguments",
    &[],
    None,
    true,
    true,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::constant_arguments::analyze(context.yagni_index.ok_or_else(|| "YAGNI index is unavailable".to_owned())?)))
}
