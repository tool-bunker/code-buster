use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "diff-quality",
    "diff-quality",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::diff_quality_rules::analyze(context.source_context)))
}
