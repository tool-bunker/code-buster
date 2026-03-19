// Direct console output in Java applications bypasses logging policy and is best detected separately from other API misuse.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports direct Java standard-output and standard-error logging.
final SourcePatternRule javaSystemOutRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-system-out',
    defaultSeverity: RuleSeverity.info,
    group: 'nim-style',
    title: 'Review system out',
    why:
        'Direct console output is hard to route, filter, or correlate in services.',
    suggestion: "Use the project's logging framework.",
    languages: <String>['java'],
  ),
  pattern: RegExp(r'System\.(?:out|err)\.println\s*\('),
  pathExclusion: _isJavaTestSource,
  message: 'System.out/System.err logging used',
  confidence: 'medium',
);

bool _isJavaTestSource(String path) => RegExp(
  r'(^|/)(?:src/test|tests?)(/|$)',
).hasMatch(path.replaceAll('\\', '/').toLowerCase());
