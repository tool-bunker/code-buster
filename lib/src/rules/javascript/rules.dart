// The JavaScript registry combines module, TypeScript, Node, and source-text checks in a stable execution order.

import '../../core/models.dart';
import '../../core/rule.dart';

import 'node_fs_constant_import.dart';
import 'typescript_source_rule.dart';

/// Self-contained JavaScript and TypeScript rules in deterministic order.
final RuleRegistry javascriptRuleRegistry = RuleRegistry(<CodeBusterRule>[
  const JavaScriptNodeFsConstantImportRule(),
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
