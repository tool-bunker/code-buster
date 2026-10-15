use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "sql",
    "sql",
    &["sql"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::sql_rules::analyze(context.source_context, &context.prepared.config)))
}
