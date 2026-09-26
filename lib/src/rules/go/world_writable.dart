// File modes that grant write access to everyone are usually accidental and can be recognized directly in Go filesystem calls.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports literal world-writable modes passed to Go file APIs.
const GoWorldWritableRule goWorldWritableRule = GoWorldWritableRule();

/// Reports effective world-writable file creation and permission changes.
final class GoWorldWritableRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoWorldWritableRule()
    : super(
        const RuleMetadata(
          id: 'go-world-writable',
          defaultSeverity: RuleSeverity.warn,
          group: 'security',
          title: 'Avoid world-writable permissions',
          why: 'World-writable files can be modified by unrelated local users.',
          suggestion:
              'Use the least permissive mode required by the application.',
          securityKind: SecurityFindingKind.vulnerability,
          languages: <String>['go'],
          version: 5,
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      for (final RegExpMatch match in _permissionCall.allMatches(
        source.value,
      )) {
        final String? flags = match.namedGroup('flags');
        if (flags != null && !_createsFile(flags, source.value)) continue;
        yield report(
          context,
          path: source.key,
          line:
              1 +
              '\n'.allMatches(source.value.substring(0, match.start)).length,
          message: 'world-writable file permission used',
          confidence: 'high',
        );
      }
    }
  }

  static final RegExp _permissionCall = RegExp(
    r'os\.(?:Chmod\s*\([^,\n]+|WriteFile\s*\([^,\n]+,[^,\n]+|OpenFile\s*\([^,\n]+,\s*(?<flags>[^,\n]+))\s*,\s*(?:0[oO]|0)?[0-7]*[2367]\b',
  );

  static bool _createsFile(String flags, String source) {
    if (RegExp(r'\bos\.O_CREATE\b').hasMatch(flags)) return true;
    final String identifier = flags.trim();
    if (!RegExp(r'^[A-Za-z_]\w*$').hasMatch(identifier)) return false;
    return RegExp(
      '\\b${RegExp.escape(identifier)}\\s*:?=\\s*[^\\n]*\\bos\\.O_CREATE\\b',
    ).hasMatch(source);
  }
}
