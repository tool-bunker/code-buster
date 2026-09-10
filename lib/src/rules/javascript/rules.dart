// The JavaScript registry combines module, TypeScript, Node, and source-text checks in a stable execution order.

import '../../core/models.dart';
import '../../core/rule.dart';

import '../csharp/oop_rules.dart';
import 'node_fs_constant_import.dart';
import 'typescript_source_rule.dart';

/// Self-contained JavaScript and TypeScript rules in deterministic order.
final RuleRegistry javascriptRuleRegistry = RuleRegistry(<CodeBusterRule>[
  const JavaScriptNodeFsConstantImportRule(),
  TypeScriptOopRule('oop-data-clump'),
  for (final String id in <String>[
    'oop-interface-segregation-pressure',
    'oop-refused-bequest',
    'oop-middle-man-delegation',
    'oop-repeated-strategy-dispatch',
    'oop-state-behavior-candidate',
    'oop-feature-envy',
    'oop-service-locator-dependency',
    'oop-repeated-observer-notification',
    'oop-message-chain',
    'oop-factory-bypass',
    'oop-facade-bypass',
    'oop-repository-bypass',
    'oop-proxy-bypass',
    'oop-repeated-adapter-mapping',
    'oop-template-workflow-candidate',
  ])
    CSharpOopRule(id),
  TypeScriptSourceRule(
    id: 'ts-any',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-await-in-loop',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-console',
    severity: RuleSeverity.info,
    group: 'nim-style',
    why:
        'Console logging in app/library code can leak data and create noisy production output.',
    suggestion:
        'Use a structured logger or remove debug logging before release.',
  ),
  TypeScriptSourceRule(
    id: 'ts-debugger',
    severity: RuleSeverity.warn,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-eval',
    severity: RuleSeverity.error,
    group: 'security',
  ),
  TypeScriptSourceRule(
    id: 'ts-floating-promise',
    severity: RuleSeverity.warn,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-hardcoded-secret',
    severity: RuleSeverity.warn,
    group: 'security',
  ),
  TypeScriptSourceRule(
    id: 'ts-inner-html',
    severity: RuleSeverity.warn,
    group: 'security',
  ),
  TypeScriptSourceRule(
    id: 'ts-json-parse-unsafe',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-localstorage-json',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  TypeScriptSourceRule(
    id: 'ts-non-null-assertion',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
]);
