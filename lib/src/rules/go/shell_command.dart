// Invoking a shell with -c changes argument data into executable syntax; this rule isolates that injection-prone boundary.

import '../../core/models.dart';
import '../../core/rule.dart';

/// Reports Go command execution through a shell `-c` boundary.
final SourcePatternRule goShellCommandRule = SourcePatternRule(
  metadata: const RuleMetadata(
    id: 'go-shell-command',
    defaultSeverity: RuleSeverity.warn,
    group: 'security',
    title: 'Avoid shell command strings',
    why: 'Shell -c introduces expansion and command-injection risk.',
    suggestion:
        'Invoke the target executable directly with separate arguments.',
    languages: <String>['go'],
  ),
  pattern: RegExp(r'''exec\.Command(?:Context)?\s*\([^,]+,\s*["']-c["']'''),
  message: 'shell command execution with -c expands an injection boundary',
  codeFlowMessage: 'shell command execution sink',
  includeCommentsAndStrings: true,
);
