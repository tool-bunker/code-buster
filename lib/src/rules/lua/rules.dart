// The Lua registry defines the exact checks enabled when a Lua plugin analyzes a repository.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'lua_rule_analysis.dart';

/// One independently registered Lua/Luau source rule.
final class LuaSourceRule extends SelfContainedRule {
  /// Creates a Lua rule with canonical metadata.
  LuaSourceRule({
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
           title: 'Review ${id.substring(4).replaceAll('-', ' ')}',
           why:
               why ??
               'This scripting construct can weaken correctness, security, or runtime performance.',
           suggestion:
               suggestion ??
               'Use the safer explicit pattern described by the rule.',
           languages: const <String>['lua'],
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => LuaRuleAnalysis()
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

/// Self-contained Lua and Luau rules in deterministic execution order.
final RuleRegistry luaRuleRegistry = RuleRegistry(<CodeBusterRule>[
  LuaSourceRule(
    id: 'lua-global-assignment',
    severity: RuleSeverity.warn,
    group: 'nim-style',
  ),
  LuaSourceRule(
    id: 'lua-loadstring',
    severity: RuleSeverity.error,
    group: 'security',
  ),
  LuaSourceRule(
    id: 'lua-mutate-pairs',
    severity: RuleSeverity.warn,
    group: 'nim-style',
  ),
  LuaSourceRule(
    id: 'lua-os-execute',
    severity: RuleSeverity.warn,
    group: 'security',
    why:
        'Shell execution can introduce command injection when command text includes input.',
    suggestion:
        'Avoid shelling out or validate/allow-list arguments carefully.',
  ),
  LuaSourceRule(
    id: 'lua-pcall-swallow',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  LuaSourceRule(
    id: 'lua-print-in-loop',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
  LuaSourceRule(
    id: 'lua-table-alloc-in-loop',
    severity: RuleSeverity.info,
    group: 'nim-style',
  ),
]);
