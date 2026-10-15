use super::*;

pub(super) const PACK: RulePack = RulePack::after_main(
    "yagni-concentration",
    "yagni-concentration",
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(
        crate::yagni_concentration::analyze(
            context.prior_findings,
            &context.prepared.config,
        ),
    ))
}
