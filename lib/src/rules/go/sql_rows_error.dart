// Database row iteration can stop on an underlying error that must be checked after the loop.

import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import '../../core/rule.dart';
import '../../engine/analysis.dart';
import '../../languages/go/go_adapter.dart';

/// Reports queried Go row iterators whose terminal error is never checked.
final class GoSqlRowsErrorRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoSqlRowsErrorRule()
    : super(
        const RuleMetadata(
          id: 'go-sql-rows-error-not-checked',
          defaultSeverity: RuleSeverity.warn,
          group: 'correctness',
          title: 'Check Go SQL row iteration errors',
          why:
              'Rows.Next can stop because iteration failed, and omitting Rows.Err can convert a partial result into apparent success.',
          suggestion:
              'After the iteration loop, check rows.Err() and propagate or handle the error.',
          semanticMaturity: RuleSemanticMaturity.token,
          requirements: <RuleAnalysisRequirement>{
            RuleAnalysisRequirement.functions,
          },
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.correctness},
          languages: <String>['go'],
          languageVersions: <String, String>{'go': '>=1.13'},
          version: 1,
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    final GoAdapter adapter = GoAdapter();
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      for (final FunctionSource function in adapter.functions(<String, String>{
        source.key: source.value,
      })) {
        for (final RegExpMatch query in _query.allMatches(function.source)) {
          final String rows = query.requiredNamedGroup('rows');
          final String tail = function.source.substring(query.end);
          final RegExpMatch? iteration = cachedRegExp(
            '\\b${RegExp.escape(rows)}\\.Next\\s*\\(\\s*\\)',
          ).firstMatch(tail);
          if (iteration == null ||
              cachedRegExp(
                '\\b${RegExp.escape(rows)}\\.Err\\s*\\(\\s*\\)',
              ).hasMatch(tail)) {
            continue;
          }
          yield report(
            context,
            path: source.key,
            line:
                function.line +
                '\n'
                    .allMatches(
                      function.source.substring(0, query.end + iteration.start),
                    )
                    .length,
            message: 'SQL row iteration does not check `$rows.Err()`',
            confidence: 'high',
          );
        }
      }
    }
  }

  static final RegExp _query = cachedRegExp(
    r'\b(?<rows>[A-Za-z_]\w*)\s*,\s*(?:[A-Za-z_]\w*|_)\s*:=\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.Query(?:Context)?\s*\(',
  );
}
