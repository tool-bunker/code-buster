// The Wren registry turns its coordinated source analysis into discoverable rules with stable metadata.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'wren_rule_analysis.dart';

/// One independently registered Wren source rule.
final class WrenSourceRule extends SelfContainedRule {
  /// Creates a Wren rule with canonical metadata.
  WrenSourceRule({
    required String id,
    required RuleSeverity severity,
    String? why,
    String? suggestion,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: 'nim-style',
           title: 'Review ${id.substring(5).replaceAll('-', ' ')}',
           why:
               why ??
               'This Wren construct can weaken reliability, performance, or module boundaries.',
           suggestion:
               suggestion ??
               'Use the safer explicit Wren pattern described by the rule.',
           languages: const <String>['wren'],
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => WrenRuleAnalysis()
      .findings(context.sources, metadata.id)
      .map(
        (Finding finding) => context.report(
          metadata: metadata,
          path: finding.path,
          line: finding.line,
          endLine: finding.endLine,
          message: finding.message,
          confidence: finding.confidence,
        ),
      );
}

/// Self-contained Wren rules in deterministic execution order.
final RuleRegistry wrenRuleRegistry = RuleRegistry(<CodeBusterRule>[
  WrenSourceRule(id: 'wren-broad-import', severity: RuleSeverity.info),
  WrenSourceRule(id: 'wren-fiber-abort', severity: RuleSeverity.warn),
  WrenSourceRule(id: 'wren-fiber-call', severity: RuleSeverity.info),
  WrenSourceRule(id: 'wren-foreign-boundary', severity: RuleSeverity.info),
  WrenSourceRule(id: 'wren-inheritance', severity: RuleSeverity.info),
  WrenSourceRule(
    id: 'wren-number-parse-unchecked',
    severity: RuleSeverity.info,
    why: 'Num.fromString can return null for invalid input.',
    suggestion:
        'Check for null and report invalid external input before using the value.',
  ),
  WrenSourceRule(id: 'wren-print-in-loop', severity: RuleSeverity.warn),
  WrenSourceRule(id: 'wren-system-print', severity: RuleSeverity.info),
]);
