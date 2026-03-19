// Printing stack traces directly bypasses structured logging and can disclose internals, especially in server code.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports direct Java stack-trace printing.
final SourcePatternRule javaPrintStacktraceRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-print-stacktrace',
    defaultSeverity: RuleSeverity.info,
    group: 'nim-style',
    title: 'Review print stacktrace',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    languages: <String>['java'],
  ),
  pattern: RegExp(r'\.printStackTrace\s*\('),
  message: 'printStackTrace used',
  confidence: 'medium',
);
