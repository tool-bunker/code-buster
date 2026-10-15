use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "dart-model-duplication",
    "dart-model-duplication",
    &[],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    if context.prepared.config.duplication_mode != "semantic" {
        return Ok(RulePackOutput::default());
    }
    Ok(RulePackOutput::findings(
        crate::dart_model_duplication::overlapping_models(context.source_context.sources()),
    ))
}
