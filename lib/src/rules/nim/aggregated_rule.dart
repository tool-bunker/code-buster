// Legacy-compatible Nim analysis emits many findings at once; this wrapper lets the shared engine treat that pass as registered rules.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'metadata.dart';
import 'nim_rule_analysis.dart';

/// One independently registered rule backed by the shared Nim analysis.
final class NimAggregatedRule extends SelfContainedRule {
  /// Creates a Nim rule from generated canonical metadata.
  const NimAggregatedRule(super.metadata);

  static final Expando<List<Finding>> _findingsBySources =
      Expando<List<Finding>>('nim-rule-findings');

  @override
  Iterable<Finding> analyze(RuleContext context) {
    final List<Finding> findings = _findingsBySources[context.sources] ??=
        NimRuleAnalysis().analyze(context.sources);
    return findings
        .where((Finding finding) => finding.code == metadata.id)
        .map(
          (Finding finding) => context.report(
            metadata: metadata,
            path: finding.path,
            line: finding.line,
            endLine: finding.endLine,
            message: finding.message,
            confidence: finding.confidence,
            relatedFiles: finding.relatedFiles,
            snippet: finding.snippet,
            codeFlow: finding.codeFlow,
          ),
        );
  }
}

/// Executable Nim rules in canonical generated order.
final List<CodeBusterRule> nimAggregatedRules = <CodeBusterRule>[
  for (final RuleMetadata metadata in nimRuleCatalog.values)
    NimAggregatedRule(metadata),
];
