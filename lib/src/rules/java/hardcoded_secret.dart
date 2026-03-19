// Credential-shaped Java constants need a focused security rule with conservative naming and value evidence.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'java_lexical.dart';

/// Reports credential-like Java assignments to string literals.
final class JavaHardcodedSecretRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const JavaHardcodedSecretRule()
    : super(
        const RuleMetadata(
          id: 'java-hardcoded-secret',
          defaultSeverity: RuleSeverity.warn,
          group: 'security',
          title: 'Review hardcoded secret',
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
        final String line = scanned.code;
        final String lower = line.toLowerCase();
        final RegExpMatch? assignment = _literalAssignment.firstMatch(line);
        if (assignment == null) {
          continue;
        }
        final String identifier = assignment.group(1)!.toLowerCase();
        final String literal = assignment.group(2)!.toLowerCase();
        if (!_secretIdentifier.hasMatch(identifier) ||
            _nonCredentialKey.hasMatch(identifier) ||
            (_credentialPlaceholder.hasMatch(literal) &&
                identifier.split('_').contains(literal)) ||
            lower.contains('system.getenv') ||
            lower.contains('getproperty')) {
          continue;
        }
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: 'possible hardcoded secret',
          confidence: 'medium',
        );
      }
    }
  }

  static final RegExp _literalAssignment = RegExp(
    r'''(?:^|[^\w$"'])([A-Za-z_$][\w$]*)\s*=\s*"((?:\\.|[^"\\])*)"\s*;''',
  );
  static final RegExp _secretIdentifier = RegExp(
    r'(?:^|_)(?:token|secret|password|passwd|api_?key|nonce|salt)(?:$|_)',
    caseSensitive: false,
  );
  static final RegExp _nonCredentialKey = RegExp(
    r'(?:^|_)(?:map|preference|package|action|type|path|error|width|height|quality)(?:_|$)',
    caseSensitive: false,
  );
  static final RegExp _credentialPlaceholder = RegExp(
    r'^(?:token|secret|password|passwd|api[_-]?key|nonce|salt)$',
    caseSensitive: false,
  );
}
