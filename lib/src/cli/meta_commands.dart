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

/// Installation channel used by `cb update`.
enum UpdateChannel { homebrew, pubGlobal, native, sourceCheckout, unsupported }

/// One deterministic self-update execution plan.
final class UpdatePlan {
  const UpdatePlan({
    required this.channel,
    required this.executable,
    required this.arguments,
    required this.description,
    this.environment,
    this.downloadUrl,
  });

  final UpdateChannel channel;
  final String executable;
  final List<String> arguments;
  final String description;
  final Map<String, String>? environment;
  final String? downloadUrl;
}

typedef UpdateProcessRunner =
    ProcessResult Function(
      String executable,
      List<String> arguments,
      Map<String, String>? environment,
    );

/// Updates Code Buster through the channel that installed the running command.
final class UpdateCommand implements CliCommandHandler {
  const UpdateCommand({
    this.executablePath,
    this.scriptPath,
    this.operatingSystem,
    UpdateProcessRunner? processRunner,
  }) : _processRunner = processRunner;

  static const String _unixInstaller =
      'https://codebuster.toolbunker.dev/install';

  final String? executablePath;
  final String? scriptPath;
  final String? operatingSystem;
  final UpdateProcessRunner? _processRunner;

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.update,
  };

  /// Selects an update channel without changing the machine.
  UpdatePlan plan() {
    final String executable = executablePath ?? Platform.resolvedExecutable;
    final String script = scriptPath ?? Platform.script.toFilePath();
    final String os = operatingSystem ?? Platform.operatingSystem;
    final String normalizedExecutable = executable.replaceAll(r'\', '/');
    final String normalizedScript = script.replaceAll(r'\', '/');

    if (normalizedExecutable.contains('/Cellar/')) {
      return const UpdatePlan(
        channel: UpdateChannel.homebrew,
        executable: 'brew',
        arguments: <String>['upgrade', 'tool-bunker/tap/code-buster'],
        description: 'Update Code Buster with Homebrew',
      );
    }
    if (normalizedScript.contains('/.pub-cache/') ||
        normalizedScript.toLowerCase().contains('/pub/cache/')) {
      return const UpdatePlan(
        channel: UpdateChannel.pubGlobal,
        executable: 'dart',
        arguments: <String>['pub', 'global', 'activate', 'code_buster'],
        description: 'Update Code Buster from pub.dev',
      );
    }
    final String executableName = normalizedExecutable
        .split('/')
        .last
        .toLowerCase();
    if (executableName == 'dart' || executableName == 'dartaotruntime') {
      return const UpdatePlan(
        channel: UpdateChannel.sourceCheckout,
        executable: '',
        arguments: <String>[],
        description:
            'This command is running from source; update the checkout with Git and rebuild it.',
      );
    }
    if (os != 'macos' && os != 'linux' && os != 'windows') {
      return UpdatePlan(
        channel: UpdateChannel.unsupported,
        executable: '',
        arguments: const <String>[],
        description: 'Self-update is not supported on $os.',
      );
    }
    if (os == 'windows') {
      return const UpdatePlan(
        channel: UpdateChannel.unsupported,
        executable: '',
        arguments: <String>[],
        description:
            'A running Windows executable cannot replace itself safely. Update with: irm https://codebuster.toolbunker.dev/install.ps1 | iex',
      );
    }
    final String parentName = normalizedExecutable
        .split('/')
        .reversed
        .skip(1)
        .first
        .toLowerCase();
    if (parentName != 'bin') {
      return const UpdatePlan(
        channel: UpdateChannel.sourceCheckout,
        executable: '',
        arguments: <String>[],
        description:
            'This executable is not in a managed bin directory; update its source or installer manually.',
      );
    }

    final String prefix = File(executable).parent.parent.path;
    return UpdatePlan(
      channel: UpdateChannel.native,
      executable: '/bin/sh',
      arguments: const <String>[],
      environment: <String, String>{'PREFIX': prefix},
      downloadUrl: _unixInstaller,
      description: 'Update the verified native $os release',
    );
  }

  @override
  int execute(CodeBusterCliOptions options) {
    final UpdatePlan update = plan();
    stdout.writeln(update.description);
    if (update.channel == UpdateChannel.sourceCheckout ||
        update.channel == UpdateChannel.unsupported) {
      return 2;
    }
    if (options.dryRun) {
      stdout.writeln(_dryRunCommand(update));
      return 0;
    }
    if (update.channel != UpdateChannel.native) {
      return _run(update.executable, update.arguments, update.environment);
    }

    final Directory temporary = Directory.systemTemp.createTempSync(
      'code-buster-update-',
    );
    try {
      const String extension = '.sh';
      final String installer = '${temporary.path}/install$extension';
      final int download = _run('curl', <String>[
        '-fsSL',
        update.downloadUrl!,
        '-o',
        installer,
      ], null);
      if (download != 0) return download;
      return _run(update.executable, <String>[installer], update.environment);
    } finally {
      temporary.deleteSync(recursive: true);
    }
  }

  int _run(
    String executable,
    List<String> arguments,
    Map<String, String>? environment,
  ) {
    final ProcessResult result = (_processRunner ?? _defaultProcessRunner)(
      executable,
      arguments,
      environment,
    );
    if (result.stdout.toString().isNotEmpty) stdout.write(result.stdout);
    if (result.stderr.toString().isNotEmpty) stderr.write(result.stderr);
    return result.exitCode;
  }

  static ProcessResult _defaultProcessRunner(
    String executable,
    List<String> arguments,
    Map<String, String>? environment,
  ) => Process.runSync(executable, arguments, environment: environment);

  static String _dryRunCommand(UpdatePlan update) {
    if (update.channel == UpdateChannel.native) {
      return 'Would download ${update.downloadUrl} and run the verified installer.';
    }
    return 'Would run: ${update.executable} ${update.arguments.join(' ')}';
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
