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
          version: 2,
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
        final String identifier = assignment.group(1)!;
        final String literal = assignment.group(2)!;
        final String lowerIdentifier = identifier.toLowerCase();
        final String lowerLiteral = literal.toLowerCase();
        final String normalizedIdentifier = lowerIdentifier.replaceAll(
          RegExp(r'[^a-z0-9]'),
          '',
        );
        final String normalizedLiteral = lowerLiteral.replaceAll(
          RegExp(r'[^a-z0-9]'),
          '',
        );
        if (!_secretIdentifier.hasMatch(lowerIdentifier) ||
            literal.trim().isEmpty ||
            _isSymbolicCredentialReference(
              identifier,
              literal,
              normalizedIdentifier,
              normalizedLiteral,
            ) ||
            _nonCredentialKey.hasMatch(lowerIdentifier) ||
            _nonCredentialRole.hasMatch(lowerIdentifier) ||
            normalizedIdentifier == normalizedLiteral ||
            (RegExp(r'^\d+$').hasMatch(normalizedLiteral) &&
                normalizedLiteral.length < 8) ||
            _symbolicLiteral.hasMatch(literal) ||
            _placeholderLiteral.hasMatch(normalizedLiteral) ||
            (_credentialPlaceholder.hasMatch(lowerLiteral) &&
                lowerIdentifier.split('_').contains(lowerLiteral)) ||
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
    r'(?:^|_)(?:token|secret|password|passwd|api_?(?:key|secret)|nonce|salt)(?:$|_)',
    caseSensitive: false,
  );
  static final RegExp _nonCredentialKey = RegExp(
    r'(?:^|_)(?:map|preference|package|action|type|path|error|width|height|quality)(?:_|$)',
    caseSensitive: false,
  );

  static bool _isSymbolicCredentialReference(
    String identifier,
    String literal,
    String normalizedIdentifier,
    String normalizedLiteral,
  ) {
    if (RegExp(r'^[A-Z][A-Z0-9_]*$').hasMatch(identifier) &&
        (literal.contains('%') || literal.contains("{{"))) {
      return true;
    }
    if (literal.contains('-') &&
        normalizedLiteral.endsWith(normalizedIdentifier)) {
      return true;
    }
    return identifier.toLowerCase().endsWith('_key') &&
        normalizedIdentifier.substring(
              0,
              normalizedIdentifier.length - 'key'.length,
            ) ==
            normalizedLiteral;
  }

  static final RegExp _nonCredentialRole = RegExp(
    r'(?:^|_)(?:prefix|suffix|cache|header|claim|message|name|path|pattern|regex|property|success|failure|template|format)(?:_|$)',
    caseSensitive: false,
  );
  static final RegExp _symbolicLiteral = RegExp(
    r'^(?:[A-Z][A-Z0-9_]*|[A-Za-z][A-Za-z0-9]*(?:[.:][A-Za-z0-9_]+)+|[A-Za-z0-9_]+[:_])$',
  );
  static final RegExp _placeholderLiteral = RegExp(
    r'^(?:changeme|placeholder|example|test|your(?:token|secret|password|apikey)|(?:fake|mock|dummy|test)[a-z0-9]*(?:key|token|secret|password|passwd)|(?:asdf){2,})$',
  );
  static final RegExp _credentialPlaceholder = RegExp(
    r'^(?:token|secret|password|passwd|api[_-]?(?:key|secret)|nonce|salt)$',
    caseSensitive: false,
  );
}
