// File modes that grant write access to everyone are usually accidental and can be recognized directly in Go filesystem calls.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports world-writable modes passed to Go's `os.Chmod`.
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
  ),
  pattern: RegExp(r'os\.Chmod\s*\([^,]+,\s*0?777\s*\)'),
  message: 'world-writable file permission used',
);
