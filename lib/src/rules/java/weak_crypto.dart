// Known-obsolete Java digest and cipher algorithms are identifiable at their API boundary and require security-specific remediation.

import '../../core/models.dart';
import '../../core/rule.dart';
import 'java_lexical.dart';

/// Reports obsolete cryptography only where the algorithm protects security data.
final class JavaWeakCryptoRule extends SelfContainedRule {
  const JavaWeakCryptoRule()
    : super(
        const RuleMetadata(
          id: 'java-weak-crypto',
          defaultSeverity: RuleSeverity.warn,
          group: 'security',
          title: 'Review weak crypto',
          why:
              'Obsolete cryptography can make credentials, signatures, or encrypted data recoverable.',
          suggestion:
              'Use a current password KDF, digest, MAC, or authenticated cipher.',
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
        if (!_obsoleteCipher.hasMatch(scanned.code) &&
            !(_legacyDigest.hasMatch(scanned.code) &&
                _hasSecurityContext(lines, index))) {
          continue;
        }
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: 'weak cryptography referenced',
          confidence: 'medium',
        );
      }
    }
  }

  static bool _hasSecurityContext(List<String> lines, int index) {
    final StringBuffer context = StringBuffer(lines[index].toLowerCase());
    final int first = index > 12 ? index - 12 : 0;
    for (var previous = index - 1; previous >= first; previous--) {
      final String candidate = lines[previous];
      if (RegExp(
        r'\b[A-Za-z_$][\w$]*\s*\([^;]*\)\s*(?:\{|$)',
      ).hasMatch(candidate)) {
        context.write(' ${candidate.toLowerCase()}');
        break;
      }
    }
    return RegExp(
      r'\b(?:auth|credential|password|passwd|secret|token|signature|signing|certificate|encryption|encrypt|decrypt|keyderivation|key derivation)',
    ).hasMatch(context.toString());
  }

  static final RegExp _legacyDigest = RegExp(
    r'\bMessageDigest\s*\.\s*getInstance\s*\(\s*"[^"]*\b(?:MD5|SHA-?1)\b',
    caseSensitive: false,
  );
  static final RegExp _obsoleteCipher = RegExp(
    r'\b(?:Cipher|Mac|SecretKeyFactory|KeyGenerator)\s*\.\s*getInstance\s*\(\s*"[^"]*\b(?:HmacSHA1|DES|RC4)\b',
    caseSensitive: false,
  );
}

/// Canonical Java weak-cryptography rule.
const JavaWeakCryptoRule javaWeakCryptoRule = JavaWeakCryptoRule();
