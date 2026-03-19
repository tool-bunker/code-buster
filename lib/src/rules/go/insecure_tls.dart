// Disabling certificate verification is easy in Go configuration literals and dangerous enough to deserve a dedicated security finding.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports Go TLS clients that disable certificate verification.
final SourcePatternRule goInsecureTlsRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'go-insecure-tls',
    defaultSeverity: RuleSeverity.error,
    group: 'security',
    title: 'Keep TLS certificate verification enabled',
    why:
        'Disabling certificate verification permits machine-in-the-middle attacks.',
    suggestion: 'Use trusted roots or explicit certificate pinning instead.',
    securityKind: SecurityFindingKind.vulnerability,
    languages: <String>['go'],
  ),
  pattern: RegExp(r'InsecureSkipVerify\s*:\s*true'),
  message: 'TLS certificate verification is disabled',
  codeFlowMessage: 'TLS verification disabled here',
);
