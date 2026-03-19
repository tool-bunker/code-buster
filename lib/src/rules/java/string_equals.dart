// Using == for Java strings compares identity rather than content, a common correctness bug with a precise source shape.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'java_lexical.dart';

/// Reports Java string literals compared with identity operators.
final JavaStringEqualsRule javaStringEqualsRule = JavaStringEqualsRule();

/// Detects identity comparisons with Java string literals.
final class JavaStringEqualsRule extends SelfContainedRule {
  /// Creates the stateless rule.
  JavaStringEqualsRule()
    : super(
        const RuleMetadata(
          id: 'java-string-equals',
          defaultSeverity: RuleSeverity.info,
          group: 'nim-style',
          title: 'Review string equals',
          why:
              'This Java construct can weaken correctness, observability, or security.',
          suggestion:
              'Use the safer Java API or pattern described by the rule.',
          languages: <String>['java'],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      final List<String> lines = context.linesFor(source.key);
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) scanned =
            javaCodeWithoutComments(
              lines[index],
              inBlockComment: inBlockComment,
            );
        inBlockComment = scanned.inBlockComment;
        if (!_stringIdentity.hasMatch(scanned.code)) {
          continue;
        }
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: 'string compared with ==/!=',
          confidence: 'medium',
        );
      }
    }
  }

  static final RegExp _stringIdentity = RegExp(
    r'(?:==|!=)\s*"(?:\\.|[^"\\])*"|"(?:\\.|[^"\\])*"\s*(?:==|!=)',
  );
}
