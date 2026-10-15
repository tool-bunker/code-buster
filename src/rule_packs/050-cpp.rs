use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "cpp",
    "cpp",
    &["c", "cpp", "objective-c"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::cpp_rules::analyze(context.source_context)))
}
