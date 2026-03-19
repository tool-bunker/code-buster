// Known-obsolete Java digest and cipher algorithms are identifiable at their API boundary and require security-specific remediation.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports references to obsolete Java cryptographic algorithms.
final SourcePatternRule javaWeakCryptoRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-weak-crypto',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review weak crypto',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    languages: <String>['java'],
  ),
  pattern: RegExp(
    r'\b(?:MessageDigest|Cipher|Mac|SecretKeyFactory|KeyGenerator)\s*\.\s*getInstance\s*\(\s*"[^"]*\b(?:MD5|SHA-?1|HmacSHA1|DES|RC4)\b',
    caseSensitive: false,
  ),
  message: 'weak cryptography referenced',
  confidence: 'medium',
  includeCommentsAndStrings: true,
);
