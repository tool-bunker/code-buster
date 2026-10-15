use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "html",
    "html",
    &["html"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::html_rules::analyze(context.source_context.sources())))
}
