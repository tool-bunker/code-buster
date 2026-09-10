// File modes that grant write access to everyone are usually accidental and can be recognized directly in Go filesystem calls.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports literal world-writable modes passed to Go file APIs.
final SourcePatternRule goWorldWritableRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'go-world-writable',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Avoid world-writable permissions',
    why: 'World-writable files can be modified by unrelated local users.',
    suggestion: 'Use the least permissive mode required by the application.',
    securityKind: SecurityFindingKind.vulnerability,
    languages: <String>['go'],
    version: 3,
  ),
  pattern: RegExp(
    r'os\.(?:Chmod\s*\([^,\n]+|WriteFile\s*\([^,\n]+,[^,\n]+|OpenFile\s*\([^,\n]+,[^,\n]+)\s*,\s*(?:0[oO]|0)?[0-7]*[2367]\b',
  ),
  message: 'world-writable file permission used',
);
