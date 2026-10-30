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
    let output = crate::rust_rules::analyze_profiled(
        context.source_context.sources(),
        context.functions,
        context.collect_timings,
    );
    Ok(RulePackOutput {
        findings: output.findings,
        shared_durations_microseconds: output.shared_durations_microseconds,
        rule_durations_microseconds: output.rule_durations_microseconds,
    })
}
