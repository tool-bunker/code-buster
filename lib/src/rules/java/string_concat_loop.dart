// Growing a String in a loop repeatedly copies old content and can become unexpectedly slow.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'java_lexical.dart';

/// Reports accumulation into a declared String from inside a braced loop.
final class JavaStringConcatLoopRule extends SelfContainedRule {
  /// Creates the stateless loop-concatenation rule.
  const JavaStringConcatLoopRule()
    : super(
        const RuleMetadata(
          id: 'java-string-concat-in-loop',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Avoid Java String concatenation in loops',
          why:
              'Repeated immutable String concatenation can copy the growing prefix on every iteration.',
          suggestion:
              'Accumulate with StringBuilder and convert to String after the loop.',
          semanticMaturity: RuleSemanticMaturity.token,
          taxonomy: <FindingTaxonomy>{FindingTaxonomy.performance},
          languages: <String>['java'],
          limitations: <String>[
            'Only explicitly declared String variables and braced loops are checked.',
          ],
        ),
      );

  static final RegExp _stringDeclaration = RegExp(
    r'\bString\s+([A-Za-z_]\w*)\b',
  );
  static final RegExp _loop = RegExp(
    r'\b(?:(?:for|while)\s*\([^{}]*\)|do)\s*\{',
  );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> entry in context.sources.entries) {
      final String code = _maskQuotedText(
        javaSourceWithoutComments(entry.value),
      );
      final Set<String> strings = _stringDeclaration
          .allMatches(code)
          .map((RegExpMatch match) => match.group(1)!)
          .toSet();
      if (strings.isEmpty) continue;
      final Set<int> reportedOffsets = <int>{};

      for (final RegExpMatch loop in _loop.allMatches(code)) {
        final int openBrace = code.indexOf('{', loop.start);
        final int closeBrace = _matchingBrace(code, openBrace);
        if (closeBrace == -1) continue;
        final String body = code.substring(openBrace + 1, closeBrace);
        for (final String variable in strings) {
          final RegExp concatenation = RegExp(
            '\\b${RegExp.escape(variable)}\\s*(?:\\+=|=\\s*${RegExp.escape(variable)}\\s*\\+)',
          );
          for (final RegExpMatch match in concatenation.allMatches(body)) {
            final int offset = openBrace + 1 + match.start;
            if (!reportedOffsets.add(offset)) continue;
            yield report(
              context,
              path: entry.key,
              line: 1 + '\n'.allMatches(code.substring(0, offset)).length,
              message: 'String `$variable` is concatenated inside a loop',
              confidence: 'high',
            );
          }
        }
      }
    }
  }
}

int _matchingBrace(String source, int openBrace) {
  var depth = 0;
  for (var index = openBrace; index < source.length; index++) {
    if (source[index] == '{') depth++;
    if (source[index] == '}' && --depth == 0) return index;
  }
  return -1;
}

String _maskQuotedText(String source) {
  final StringBuffer result = StringBuffer();
  String? quote;
  for (var index = 0; index < source.length; index++) {
    final String character = source[index];
    if (quote == null) {
      if (character == '"' || character == "'") {
        quote = character;
        result.write(' ');
      } else {
        result.write(character);
      }
      continue;
    }
    if (character == '\n') {
      result.write('\n');
    } else {
      result.write(' ');
    }
    if (character == '\\' && index + 1 < source.length) {
      index++;
      result.write(source[index] == '\n' ? '\n' : ' ');
    } else if (character == quote) {
      quote = null;
    }
  }
  return result.toString();
}
