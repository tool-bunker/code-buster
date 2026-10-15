use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "oop",
    "oop",
    &["dart", "csharp", "java", "javascript", "typescript"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let output = crate::oop_rules::analyze_profiled(context.source_context.sources());
    Ok(RulePackOutput {
        findings: output.findings,
        durations_milliseconds: output.durations_milliseconds,
    })
}
