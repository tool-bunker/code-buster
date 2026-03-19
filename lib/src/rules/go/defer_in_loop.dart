// A defer inside a Go loop accumulates work until the surrounding function returns, a subtle lifetime mistake worth calling out directly.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports Go `defer` statements lexically nested in loops.
final class GoDeferInLoopRule extends SelfContainedRule {
  /// Creates the stateless rule.
  const GoDeferInLoopRule()
    : super(
        const RuleMetadata(
          id: 'go-defer-in-loop',
          defaultSeverity: RuleSeverity.warn,
          group: 'core',
          title: 'Avoid defer inside long-running loops',
          why:
              'Deferred calls accumulate until the surrounding function returns.',
          suggestion:
              'Extract one iteration into a function or release resources explicitly.',
          languages: <String>['go'],
        ),
      );

  @override
  Iterable<Finding> analyze(RuleContext context) sync* {
    for (final MapEntry<String, String> source in context.sources.entries) {
      if (!source.key.endsWith('.go')) continue;
      var loopDepth = 0;
      final List<String> lines = context.linesFor(source.key);
      for (var index = 0; index < lines.length; index++) {
        final String line = lines[index].trim();
        if (line.startsWith('for ') || line == 'for {') loopDepth++;
        if (loopDepth > 0 && line.startsWith('defer ')) {
          yield report(
            context,
            path: source.key,
            line: index + 1,
            message:
                'defer inside a loop accumulates until the surrounding function returns',
            confidence: 'high',
          );
        }
        if (loopDepth > 0 && line == '}') loopDepth--;
      }
    }
  }
}
