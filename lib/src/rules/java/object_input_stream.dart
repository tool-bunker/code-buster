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
    version: 3,
    languages: <String>['java'],
  ),
  pattern: RegExp(
    r'^(?!\s*import\b)[^\n]*\bObjectInputStream\b',
    multiLine: true,
  ),
  message: 'Java native deserialization used',
  confidence: 'medium',
  oncePerFile: true,
);
