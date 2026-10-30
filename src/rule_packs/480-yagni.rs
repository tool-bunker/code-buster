use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "yagni",
    "yagni",
    &[],
    None,
    true,
    true,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let index = context
        .yagni_index
        .ok_or_else(|| "YAGNI index is unavailable".to_owned())?;
    let output = crate::yagni_rules::analyze_profiled(
        index,
        context.source_context.sources(),
        context.collect_timings,
    );
    Ok(RulePackOutput {
        findings: output.findings,
        shared_durations_microseconds: BTreeMap::new(),
        rule_durations_microseconds: output.rule_durations_microseconds,
    })
}
