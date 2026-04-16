// Doctor combines discovery, configuration, graph, and rule health checks to explain why an analysis run may be untrustworthy.

import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Checks configuration, discovery, and analysis health.
final class DoctorCommand implements CliCommandHandler {
  /// Creates the doctor command.
  const DoctorCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.doctor,
  };

  @override
  int execute(CodeBusterCliOptions options) => _doctor(options);
}

int _doctor(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(options);
  final int duplicateCount = run.findings
      .where((Finding finding) => finding.code == 'duplicate-block')
      .length;
  stdout.writeln('Code Buster doctor');
  stdout.writeln(
    '- Hidden directories are skipped by default; use explicit includes only if you want to analyze hidden tooling/vendor folders.',
  );
  if (run.coverage.isNotEmpty) {
    final List<String> reasons = run.coverage.keys.toList()..sort();
    stdout.writeln(
      '- Coverage: ${reasons.map((String reason) => '$reason=${run.coverage[reason]}').join(' ')}',
    );
  }
  if (duplicateCount > 20) {
    stdout.writeln(
      '- There are many duplicate-block findings; consider raising min_duplication_lines above ${run.config.minDuplicationLines}.',
    );
  }
  if (run.files.isEmpty) {
    stdout.writeln(
      '- No source files were discovered; check --root, --lang, and ignore_patterns.',
    );
  }
  return 0;
}
