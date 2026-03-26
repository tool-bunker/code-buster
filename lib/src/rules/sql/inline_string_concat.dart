// SQL concatenation operators can splice values into statements; this rule detects the dialect-specific inline forms.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'sql_analysis.dart';

/// Canonical metadata owned by the repository-wide SQL construction rule.
const RuleMetadata sqlInlineStringConcatMetadata = RuleMetadata(
  id: 'sql-inline-string-concat',
  defaultSeverity: RuleSeverity.warn,
  group: 'sql',
  title: 'Review inline string concat',
  why:
      'This SQL construct can create correctness, safety, or performance risk.',
  suggestion: 'Use the safer SQL pattern described by the rule.',
  version: 3,
  securityKind: SecurityFindingKind.hotspot,
  taxonomy: <FindingTaxonomy>{FindingTaxonomy.security},
  limitations: <String>['Commented-out source is excluded.'],
);

/// Repository-wide SQL construction check for non-SQL source files.
final class SqlInlineStringConcatRule implements CodeBusterRule {
  /// Creates the stateless rule.
  const SqlInlineStringConcatRule();

  static final SqlRuleAnalysis _adapter = SqlRuleAnalysis();

  @override
  RuleMetadata get metadata => sqlInlineStringConcatMetadata;

  @override
  Iterable<Finding> analyze(RuleContext context) =>
      _adapter.inlineFindings(<String, String>{
        for (final MapEntry<String, String> source in context.sources.entries)
          if (!source.key.endsWith('.sql')) source.key: source.value,
      });
}
