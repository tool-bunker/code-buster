import 'dart:io';

import 'package:toml/toml.dart';

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
    int version = 1,
    String? why,
    String? suggestion,
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: group,
           title: 'Review ${id.substring(3).replaceAll('-', ' ')}',
           version: version,
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
  Iterable<Finding> analyze(RuleContext context) {
    if (_disabledByPythonProjectPolicy(context.config.root, metadata.id)) {
      return const <Finding>[];
    }
    return PythonRuleAnalysis()
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
}

bool _disabledByPythonProjectPolicy(String root, String ruleId) {
  final File file = File('$root${Platform.pathSeparator}pyproject.toml');
  if (!file.existsSync()) return false;
  try {
    final Map<String, dynamic> values = TomlDocument.parse(
      file.readAsStringSync(),
    ).toMap();
    final Map<String, dynamic> tool =
        values['tool'] as Map<String, dynamic>? ?? const <String, dynamic>{};
    final Map<String, dynamic> pylint =
        tool['pylint'] as Map<String, dynamic>? ?? const <String, dynamic>{};
    final Map<String, dynamic> messages =
        pylint['messages_control'] as Map<String, dynamic>? ??
        const <String, dynamic>{};
    final Set<String> pylintDisabled = {
      for (final Object? value
          in messages['disable'] as List<dynamic>? ?? const <dynamic>[])
        if (value is String) value.toLowerCase(),
    };
    final Map<String, dynamic> ruff =
        tool['ruff'] as Map<String, dynamic>? ?? const <String, dynamic>{};
    final Map<String, dynamic> lint =
        ruff['lint'] as Map<String, dynamic>? ?? const <String, dynamic>{};
    final Set<String> ruffIgnored = {
      for (final Object? value
          in lint['ignore'] as List<dynamic>? ?? const <dynamic>[])
        if (value is String) value.toUpperCase(),
    };
    return switch (ruleId) {
      'py-function-naming' => pylintDisabled.contains('invalid-name'),
      'py-mutable-default' => pylintDisabled.contains(
        'dangerous-default-value',
      ),
      'py-broad-except' => pylintDisabled.contains('broad-exception-caught'),
      'py-import-not-top' => ruffIgnored.contains('E402'),
      'py-bare-except' => ruffIgnored.contains('E722'),
      _ => false,
    };
  } on Object {
    return false;
  }
}

PythonSourceRule _style(String id, {int version = 1}) => PythonSourceRule(
  id: id,
  severity: RuleSeverity.info,
  group: 'nim-style',
  version: version,
);

PythonSourceRule _security(
  String id, {
  RuleSeverity severity = RuleSeverity.info,
  int version = 1,
  String? why,
  String? suggestion,
}) => PythonSourceRule(
  id: id,
  severity: severity,
  group: 'security',
  why: why,
  version: version,
  suggestion: suggestion,
);

/// Self-contained Python rules in deterministic execution order.
final RuleRegistry pythonRuleRegistry = RuleRegistry(<CodeBusterRule>[
  _style('py-assert-runtime'),
  _security('py-async-blocking-call'),
  _style('py-backslash-continuation'),
  _style('py-bare-except', version: 2),
  _style('py-broad-except', version: 2),
  _style('py-compound-statement'),
  _security('py-debug-enabled'),
  _security('py-eval-exec', severity: RuleSeverity.error),
  _style('py-extraneous-whitespace'),
  _style('py-function-naming', version: 4),
  _security('py-hardcoded-secret', version: 3),
  _security(
    'py-insecure-tls',
    severity: RuleSeverity.warn,
    why:
        'Disabling certificate verification permits network attackers to impersonate the remote service.',
    suggestion:
        'Keep verification enabled or pass a trusted CA bundle through `verify`.',
  ),
  _style('py-import-not-top', version: 3),
  _style('py-logging-exception'),
  _style('py-multiple-imports'),
  _style('py-mutable-default', version: 2),
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
  _security('py-weak-hash', version: 2),
  _style('py-wildcard-import'),
  _security('py-yaml-load', severity: RuleSeverity.error),
]);
