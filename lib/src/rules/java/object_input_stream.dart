// Native Java deserialization can execute attacker-controlled object graphs, making ObjectInputStream use a distinct security hotspot.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports use of Java native object deserialization.
final SourcePatternRule javaObjectInputStreamRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'java-objectinputstream',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Review objectinputstream',
    why:
        'This Java construct can weaken correctness, observability, or security.',
    suggestion: 'Use the safer Java API or pattern described by the rule.',
    version: 2,
    languages: <String>['java'],
  ),
  pattern: RegExp(r'\bObjectInputStream\b'),
  message: 'Java native deserialization referenced',
  confidence: 'medium',
  oncePerFile: true,
);
