// Statement-level SQL rules share parsed boundaries and dialect context, so this base keeps their reporting behavior aligned.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'sql_analysis.dart';

/// One independently registered standalone SQL statement rule.
final class SqlStatementRule extends SelfContainedRule {
  /// Creates a statement rule with canonical metadata.
  SqlStatementRule({
    required String id,
    required RuleSeverity severity,
    int version = 1,
    List<String> limitations = const <String>[],
  }) : super(
         RuleMetadata(
           id: id,
           defaultSeverity: severity,
           group: 'sql',
           title: 'Review ${id.substring(4).replaceAll('-', ' ')}',
           why:
               'This SQL construct can create correctness, safety, or performance risk.',
           suggestion: 'Use the safer SQL pattern described by the rule.',
           version: version,
           languages: const <String>['sql'],
           limitations: limitations,
         ),
       );

  @override
  Iterable<Finding> analyze(RuleContext context) => SqlRuleAnalysis()
      .findings(
        context.sources,
        dialect: context.config.languages.contains('mysql')
            ? 'mysql'
            : 'postgres',
        checkNonConcurrentIndexes:
            metadata.id == 'sql-create-index-nonconcurrent',
      )
      .where((Finding finding) => finding.code == metadata.id)
      .map(
        (Finding finding) => context.report(
          metadata: metadata,
          path: finding.path,
          line: finding.line,
          endLine: finding.endLine,
          message: finding.message,
          confidence: finding.confidence,
          relatedFiles: finding.relatedFiles,
          snippet: finding.snippet,
          codeFlow: finding.codeFlow,
        ),
      );
}
