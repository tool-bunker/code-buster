// This registry makes the active C# checks and their execution order explicit.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'source_rules.dart';

const Set<String> _informationalRules = <String>{
  'cs-datetime-now',
  'cs-dcom-api',
  'cs-explicit-delegate-new',
  'cs-file-scoped-namespace',
  'cs-new-httpclient',
  'cs-runtime-type-alias',
  'cs-string-concat-loop',
  'cs-thread-sleep',
};
const Set<String> _securityRules = <String>{
  'cs-aptca-attribute',
  'cs-binaryformatter',
  'cs-cas-api',
  'cs-dcom-api',
  'cs-hardcoded-secret',
  'cs-process-start-input',
  'cs-public-pinvoke',
  'cs-random-security',
  'cs-remoting-api',
  'cs-sql-string-build',
  'cs-weak-crypto',
};

/// Self-contained C# rules in deterministic execution order.
final RuleRegistry csharpRuleRegistry = RuleRegistry(<CodeBusterRule>[
  for (final String id in const <String>[
    'cs-aptca-attribute',
    'cs-async-void',
    'cs-binaryformatter',
    'cs-cas-api',
    'cs-catch-system-exception',
    'cs-datetime-now',
    'cs-dcom-api',
    'cs-empty-catch',
    'cs-explicit-delegate-new',
    'cs-file-scoped-namespace',
    'cs-hardcoded-secret',
    'cs-new-httpclient',
    'cs-non-short-circuit-bool',
    'cs-process-start-input',
    'cs-public-pinvoke',
    'cs-random-security',
    'cs-remoting-api',
    'cs-runtime-type-alias',
    'cs-sql-string-build',
    'cs-string-concat-loop',
    'cs-sync-over-async',
    'cs-thread-sleep',
    'cs-using-inside-namespace',
    'cs-weak-crypto',
  ])
    CSharpSourceRule(
      id: id,
      severity: _informationalRules.contains(id)
          ? RuleSeverity.info
          : RuleSeverity.warn,
      group: _securityRules.contains(id) ? 'security' : 'nim-style',
    ),
]);
