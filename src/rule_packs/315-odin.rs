use super::*;

pub(super) const PACK: RulePack =
    RulePack::main("odin", "odin", &["odin"], None, false, false, analyze);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::languages::odin::rules::analyze(context.source_context),
    ))
}
