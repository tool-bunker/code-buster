// Catching Exception erases failure distinctions and often hides recovery mistakes, so this check reports the broad catch itself.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports broad Java exception handlers.
final SourcePatternRule javaCatchExceptionRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-catch-exception',
    defaultSeverity: RuleSeverity.warn,
    group: 'nim-style',
    title: 'Review catch exception',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    languages: <String>['java'],
  ),
  pattern: RegExp(r'catch\s*\(\s*(?:Exception|Throwable)\b'),
  message: 'broad Java exception handler',
  confidence: 'medium',
);
