use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "sql-inline",
    "sql-inline",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::sql_inline_rule::analyze(context.source_context)))
}
