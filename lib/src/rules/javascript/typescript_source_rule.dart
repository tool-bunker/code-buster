// This adapter turns TypeScript analysis findings into ordinary Code Buster rules with consistent metadata and reporting.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'typescript_rule_analysis.dart';

/// One independently registered JavaScript/TypeScript source rule.
final class TypeScriptSourceRule extends SelfContainedRule {
  /// Creates a source rule with canonical metadata.
  TypeScriptSourceRule({
    required String id,
    required RuleSeverity severity,
    required String group,
    String? why,
    String? suggestion,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title: 'Review ${id.substring(3).replaceAll('-', ' ')}',
           why:
               why ??
               'This scripting construct can weaken correctness, security, or runtime performance.',
           suggestion:
               suggestion ??
               'Use the safer explicit pattern described by the rule.',
           version: 2,
           languages: const <String>['javascript', 'typescript'],
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => TypeScriptRuleAnalysis()
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
