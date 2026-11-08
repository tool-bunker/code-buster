use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "shell",
    "shell",
    &["shell"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::shell_rules::analyze(
        context.source_context.sources(),
    )))
}
