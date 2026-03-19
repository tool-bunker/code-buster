// Thread.sleep often substitutes timing guesses for coordination; this check gives that concurrency smell its own guidance.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports direct Java thread sleeping.
final SourcePatternRule javaThreadSleepRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-thread-sleep',
    defaultSeverity: RuleSeverity.info,
    group: 'nim-style',
    title: 'Review thread sleep',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    languages: <String>['java'],
  ),
  pattern: RegExp(r'Thread\.sleep\s*\('),
  message: 'Thread.sleep used',
  confidence: 'medium',
);
