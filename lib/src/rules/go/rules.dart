// The Go registry keeps resource, networking, process, permission, and control-flow checks discoverable as one language pack.

import '../../core/rule.dart';

import 'defer_in_loop.dart';
import 'http_client_no_timeout.dart';
import 'insecure_tls.dart';
import 'response_body_not_closed.dart';
import 'shell_command.dart';
import 'world_writable.dart';

/// Self-contained Go rules in deterministic execution order.
final RuleRegistry goRuleRegistry = RuleRegistry(<CodeBusterRule>[
  const GoDeferInLoopRule(),
  goHttpClientNoTimeoutRule,
  goInsecureTlsRule,
  const GoResponseBodyNotClosedRule(),
  goShellCommandRule,
  goWorldWritableRule,
]);
