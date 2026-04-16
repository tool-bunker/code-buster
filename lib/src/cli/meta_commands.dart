// Version and shell-completion commands answer process-level questions and do not need to load or analyze a repository.

import 'dart:io';

import 'cli_command.dart';
import 'cli_contract.dart';

/// Handles `cb version`.
final class VersionCommand implements CliCommandHandler {
  /// Creates the version command.
  const VersionCommand(this.version);

  /// Version string reported to users.
  final String version;

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.version,
  };

  @override
  int execute(CodeBusterCliOptions options) {
    stdout.writeln('cb $version');
    stdout.writeln('runtime: Dart');
    return 0;
  }
}

/// Handles shell completion generation.
final class CompletionsCommand implements CliCommandHandler {
  /// Creates the completion command.
  const CompletionsCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.completions,
  };

  @override
  int execute(CodeBusterCliOptions options) {
    stdout.writeln(CodeBusterCliContract.completions(options.target ?? 'bash'));
    return 0;
  }
}
