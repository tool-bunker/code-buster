use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "duplication",
    "duplication",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::duplication::exact_findings(
            context.source_context.sources(),
            context.prepared.config.min_duplication_lines,
        ),
    ))
}
