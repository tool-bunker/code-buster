// New users need a valid starting configuration that reflects current defaults without copying a long example by hand.

import 'dart:io';

import '../config/config.dart';
import 'cli_command.dart';
import 'cli_contract.dart';

/// Creates a starter `code-buster.toml`.
final class InitCommand implements CliCommandHandler {
  /// Creates the init command.
  const InitCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.init,
  };

  @override
  int execute(CodeBusterCliOptions options) {
    final String root = options.target ?? options.root;
    final File config = File('$root${Platform.pathSeparator}code-buster.toml');
    if (config.existsSync() && !options.force) {
      stderr.writeln('config exists (use --force)');
      return 1;
    }
    config.writeAsStringSync(CodeBusterConfigLoader.starterConfig());
    stdout.writeln('created ${config.path}');
    return 0;
  }
}
