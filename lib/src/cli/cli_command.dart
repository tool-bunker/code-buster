// Command handlers conform to this small interface so dispatch can stay ignorant of each command’s implementation details.

import 'cli_contract.dart';

/// Independently executable CLI command handler.
abstract interface class CliCommandHandler {
  /// Commands implemented by this handler.
  Set<CodeBusterCommand> get commands;

  /// Executes [options] and returns a process exit code.
  int execute(CodeBusterCliOptions options);
}
