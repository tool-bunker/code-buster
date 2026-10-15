use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "rust",
    "rust",
    &["rust"],
    None,
    true,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::rust_rules::analyze_with_functions(
            context.source_context.sources(),
            context.functions,
        ),
    ))
}
