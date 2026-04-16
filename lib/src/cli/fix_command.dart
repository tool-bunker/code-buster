// Fixing is deliberately separate from finding: this command previews safe edits and only writes when the user explicitly asks.

import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Previews or applies deterministic safe fixes.
final class FixCommand implements CliCommandHandler {
  /// Creates the fix command.
  const FixCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.fix,
  };

  @override
  int execute(CodeBusterCliOptions options) => _fix(options);
}

int _fix(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(options);
  if (run.files.isEmpty && !options.allowEmpty) {
    stderr.writeln('no source files found (use --allow-empty to allow this)');
    return 1;
  }
  final List<FixResult> results = SafeFixer().apply(
    root: run.config.root,
    files: run.files,
    dryRun: options.dryRun,
  );
  final List<FixResult> changed = results
      .where((FixResult result) => result.changed)
      .toList(growable: false);
  for (final FixResult result in changed) {
    stdout.writeln('${options.dryRun ? 'would fix' : 'fixed'} ${result.path}');
  }
  if (changed.isEmpty) {
    stdout.writeln('no safe fixes needed');
  } else {
    stdout.writeln(
      '${changed.length} file(s) ${options.dryRun ? 'would change' : 'changed'}',
    );
  }
  return 0;
}
