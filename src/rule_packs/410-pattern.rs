use super::*;

pub(super) const PACK: RulePack =
    RulePack::main("pattern", "pattern", &[], None, false, false, analyze);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let findings = crate::pattern_rules::analyze(
        context.source_context.sources(),
        &context.prepared.config.pattern_rules,
    )?;
    Ok(RulePackOutput::findings(findings))
}
