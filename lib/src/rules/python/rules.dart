// The Python registry connects its coordinated analysis to stable rule IDs and the common execution pipeline.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'python_rule_analysis.dart';

/// One independently registered Python source rule.
final class PythonSourceRule extends SelfContainedRule {
  /// Creates a Python rule with canonical metadata.
  PythonSourceRule({
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
           languages: const <String>['python'],
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => PythonRuleAnalysis()
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

PythonSourceRule _style(String id) =>
    PythonSourceRule(id: id, severity: RuleSeverity.info, group: 'nim-style');

PythonSourceRule _security(
  String id, {
  RuleSeverity severity = RuleSeverity.info,
  String? why,
  String? suggestion,
}) => PythonSourceRule(
  id: id,
  severity: severity,
  group: 'security',
  why: why,
  suggestion: suggestion,
);

/// Self-contained Python rules in deterministic execution order.
final RuleRegistry pythonRuleRegistry = RuleRegistry(<CodeBusterRule>[
  _style('py-assert-runtime'),
  _security('py-async-blocking-call'),
  _style('py-backslash-continuation'),
  _style('py-bare-except'),
  _style('py-broad-except'),
  _style('py-compound-statement'),
  _security('py-debug-enabled'),
  _security('py-eval-exec', severity: RuleSeverity.error),
  _style('py-extraneous-whitespace'),
  _style('py-function-naming'),
  _security('py-hardcoded-secret'),
  _style('py-import-not-top'),
  _style('py-logging-exception'),
  _style('py-multiple-imports'),
  _style('py-mutable-default'),
  _security('py-open-no-encoding'),
  _security('py-pickle'),
  _security(
    'py-requests-timeout',
    why:
        'HTTP calls without timeouts can hang indefinitely and exhaust workers.',
    suggestion:
        'Pass an explicit timeout, e.g. `timeout=10` or a connect/read tuple.',
  ),
  _security('py-sql-string-build'),
  _security('py-subprocess-shell'),
  _security('py-tempfile-mktemp'),
  _security('py-weak-hash'),
  _style('py-wildcard-import'),
  _security('py-yaml-load', severity: RuleSeverity.error),
]);
