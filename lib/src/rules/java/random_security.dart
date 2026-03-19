// java.util.Random is fine for simulation but not secrets; this rule narrows findings to security-sensitive usage signals.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports `java.util.Random` used for credential-like values.
final class JavaRandomSecurityRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const JavaRandomSecurityRule()
    : super(
        const RuleMetadata(
          id: 'java-random-security',
          defaultSeverity: RuleSeverity.warn,
          group: 'security',
          title: 'Review random security',
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
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index];
        if (!line.contains('new Random(') ||
            !_secret.hasMatch(line.toLowerCase())) {
          continue;
        }
        yield report(
          context,
          path: source.key,
          line: index + 1,
          message: 'java.util.Random appears used for sensitive value',
          confidence: 'medium',
        );
      }
    }
  }

  static final RegExp _secret = RegExp(
    r'token|secret|password|passwd|api_key|apikey|nonce|salt|key',
  );
}
