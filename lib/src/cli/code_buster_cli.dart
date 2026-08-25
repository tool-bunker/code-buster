// The executable needs one place to parse arguments, select a handler, print usage, and translate failures into process exit codes.

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:code_buster/src/internal.dart';

import 'analysis_command.dart';
import 'baseline_command.dart';
import 'cli_command.dart';
import 'config_command.dart';
import 'doctor_command.dart';
import 'explain_command.dart';
import 'fix_command.dart';
import 'graph_command.dart';
import 'hotspots_command.dart';
import 'init_command.dart';
import 'meta_commands.dart';
import 'preview_command.dart';
import 'quality_commands.dart';
import 'repository_view_command.dart';
import 'rules_command.dart';

/// Current Code Buster command-line version.
const String version = '0.2.0';

final Map<CodeBusterCommand, CliCommandHandler> _commandHandlers =
    _buildCommandHandlers(const <CliCommandHandler>[
      AnalysisCommand(),
      BaselineCommand(),
      VersionCommand(version),
      CompletionsCommand(),
      ConfigCommand(),
      DoctorCommand(),
      ExplainCommand(),
      FixCommand(),
      GraphCommand(),
      HotspotsCommand(),
      InitCommand(),
      PreviewCommand(),
      PlanningCommand(),
      QualityCommand(),
      RepositoryViewCommand(),
      ScoreCommand(),
      RulesCommand(),
    ]);

Map<CodeBusterCommand, CliCommandHandler> _buildCommandHandlers(
  Iterable<CliCommandHandler> handlers,
) {
  final Map<CodeBusterCommand, CliCommandHandler> result =
      <CodeBusterCommand, CliCommandHandler>{};
  for (final CliCommandHandler handler in handlers) {
    for (final CodeBusterCommand command in handler.commands) {
      if (result.containsKey(command)) {
        throw StateError('duplicate CLI handler for ${command.name}');
      }
      result[command] = handler;
    }
  }
  final Set<CodeBusterCommand> missing = CodeBusterCommand.values
      .toSet()
      .difference(result.keys.toSet());
  if (missing.isNotEmpty) {
    throw StateError(
      'missing CLI handlers: ${missing.map((CodeBusterCommand command) => command.name).join(', ')}',
    );
  }
  return Map<CodeBusterCommand, CliCommandHandler>.unmodifiable(result);
}

/// Prints top-level command usage.
void printUsage() {
  stdout.writeln('Usage: cb <command> [options]');
  stdout.writeln(
    'Commands: ${CodeBusterCommand.values.map((CodeBusterCommand command) => command.name).join(' ')}',
  );
  stdout.writeln(CodeBusterCliContract.parser.usage);
}

/// Runs Code Buster and returns the process exit code.
int run(List<String> arguments) {
  try {
    if (arguments.contains('--help') || arguments.contains('-h')) {
      printUsage();
      return 0;
    }
    final CodeBusterCliOptions options = CodeBusterCliContract.parse(
      arguments.contains('--version') ? const <String>['version'] : arguments,
    );
    return _commandHandlers[options.command]!.execute(options);
  } on UsageException catch (error) {
    stderr.writeln(error.message);
    stderr.writeln(error.usage);
    return 2;
  } on FormatException catch (error) {
    stderr.writeln(error.message);
    return 2;
  }
}
