use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "rust",
    "rust",
    &["rust"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::rust_rules::analyze(context.source_context.sources())))
}
