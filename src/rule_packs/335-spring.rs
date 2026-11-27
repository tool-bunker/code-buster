use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "spring",
    "spring",
    &["java"],
    Some("spring"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::rules::frameworks::spring::analyze(context.source_context),
    ))
}
