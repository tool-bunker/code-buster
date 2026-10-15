use super::*;

pub(super) const PACK: RulePack = RulePack::main(
    "dart-core",
    "dart-core",
    &["dart"],
    None,
    false,
    false,
    analyze,
);

fn analyze(context: &RulePackContext<'_, '_, '_>) -> Result<RulePackOutput, String> {
    Ok(RulePackOutput::findings(crate::dart_core_rules::analyze_index(context.dart_index.ok_or_else(|| "Dart index is unavailable".to_owned())?)))
}
