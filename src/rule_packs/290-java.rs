use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "java",
    "java",
    &["java"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::java_rules::analyze(context.source_context)))
}
