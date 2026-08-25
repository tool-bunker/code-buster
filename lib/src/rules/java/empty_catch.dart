// A failure caught and ignored becomes much harder to diagnose when it reaches production.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'java_lexical.dart';

/// Reports Java catch blocks with no executable statements.
final class JavaEmptyCatchRule extends SelfContainedRule {
  /// Creates the stateless empty-catch rule.
  const JavaEmptyCatchRule()
    : super(
        const RuleMetadata(
          id: 'java-empty-catch',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Handle or document Java exceptions',
          why:
              'An empty catch block silently loses failures and the context needed to diagnose them.',
          suggestion:
              'Recover, rethrow, or record the exception instead of discarding it.',
          semanticMaturity: RuleSemanticMaturity.token,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.reliability},
          languages: <String>['java'],
          limitations: <String>[
            'Only catch declarations whose parameter list has no nested parentheses are checked.',
          ],
        ),
      );

  static final RegExp _emptyCatch = RegExp(
    r'\bcatch\s*\([^()]*\)\s*\{\s*\}',
    multiLine: true,
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      final String source = javaSourceWithoutComments(entry.value);
      for (final RegExpMatch match in _emptyCatch.allMatches(source)) {
        yield report(
          context,
          path: entry.key,
          line: 1 + '\n'.allMatches(source.substring(0, match.start)).length,
          message: 'catch block is empty',
          confidence: 'high',
        );
      }
    }
  }
}
