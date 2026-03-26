// The SQL registry selects statement and string-building checks according to the configured dialect.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'statement_rule.dart';

/// Self-contained SQL-language rules in deterministic execution order.
final RuleRegistry sqlRuleRegistry = RuleRegistry(<CodeBusterRule>[
  SqlStatementRule(
    id: 'sql-add-not-null-default',
    severity: RuleSeverity.warn,
    version: 2,
  ),
  SqlStatementRule(id: 'sql-case-sensitive-like', severity: RuleSeverity.info),
  SqlStatementRule(
    id: 'sql-create-index-nonconcurrent',
    severity: RuleSeverity.info,
    version: 2,
    limitations: const <String>[
      'Opt-in because transactional migration runners cannot use CONCURRENTLY.',
    ],
  ),
  SqlStatementRule(id: 'sql-delete-without-where', severity: RuleSeverity.warn),
  SqlStatementRule(
    id: 'sql-drop-table-without-if-exists',
    severity: RuleSeverity.info,
  ),
  SqlStatementRule(
    id: 'sql-leading-wildcard-like',
    severity: RuleSeverity.info,
  ),
  SqlStatementRule(
    id: 'sql-not-in-subquery-null-risk',
    severity: RuleSeverity.info,
  ),
  SqlStatementRule(id: 'sql-select-star', severity: RuleSeverity.info),
  SqlStatementRule(
    id: 'sql-update-without-where',
    severity: RuleSeverity.warn,
    version: 2,
    limitations: const <String>[
      'Only statements beginning with UPDATE are checked.',
    ],
  ),
]);
