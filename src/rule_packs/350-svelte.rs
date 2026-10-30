use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "svelte",
    "svelte",
    &[],
    Some("svelte"),
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    let mut findings = crate::svelte_rules::analyze(context.source_context.sources());
    findings.extend(crate::css_rules::analyze_svelte_styles(
        context.source_context.sources(),
    ));
    Ok(RulePackOutput::findings(findings))
}
