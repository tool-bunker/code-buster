// SQL assembled through Java string concatenation can mix code and untrusted data, warranting a dedicated injection heuristic.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports SQL statements assembled through Java string concatenation.
final SourcePatternRule javaSqlStringBuildRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-sql-string-build',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review sql string build',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    languages: <String>['java'],
  ),
  pattern: RegExp(
    r'"\s*(?:select\b[^"]*\bfrom\b|insert\s+into\b|update\b[^"]*\bset\b|delete\s+from\b)[^"]*"\s*\+\s*(?!")\S',
    caseSensitive: false,
  ),
  message: 'SQL appears concatenated',
  confidence: 'medium',
  includeCommentsAndStrings: true,
);
