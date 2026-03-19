// Go’s default HTTP client can wait forever; this rule looks for client construction that never establishes a timeout.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports empty Go HTTP clients without a configured timeout.
final SourcePatternRule goHttpClientNoTimeoutRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'go-http-client-no-timeout',
    defaultSeverity: RuleSeverity.warn,
    group: 'reliability',
    title: 'Set an HTTP client timeout',
    why:
        'A client without a timeout can wait indefinitely and exhaust resources.',
    suggestion:
        'Set http.Client.Timeout or enforce a request context deadline.',
    languages: <String>['go'],
  ),
  pattern: RegExp(r'http\.Client\s*\{\s*\}'),
  message: 'HTTP client has no timeout',
);
