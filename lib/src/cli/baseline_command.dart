// Baselines have their own lifecycle—create, update, prune, and inspect—and should not complicate normal analysis commands.

import 'dart:convert';
import 'dart:io';

import '../controls/finding_controls.dart';
import '../core/models.dart';
import '../discovery/discovery.dart';
import '../engine/analysis_runner.dart';
import 'cli_command.dart';
import 'cli_contract.dart';

/// Creates, updates, prunes, and describes analysis baselines.
final class BaselineCommand implements CliCommandHandler {
  /// Creates the baseline command.
  const BaselineCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.baseline,
  };

  @override
  int execute(CodeBusterCliOptions options) => _baseline(options);
}

int _baseline(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(
    options,
    command: CodeBusterCommand.summary,
  );
  if (run.files.isEmpty && !options.allowEmpty) {
    stderr.writeln('no source files found (use --allow-empty to allow this)');
    return 1;
  }
  final File output = File(
    options.output.isEmpty
        ? '${run.config.root}${Platform.pathSeparator}.code-buster-baseline'
        : options.output,
  );
  final List<Finding> baselineFindings = <Finding>[
    ..._nimBaselineGenericFindings(run),
    ...run.findings,
  ];
  final Set<String> existing = BaselineCodec.read(output);
  final Set<String> current = <String>{
    for (final Finding finding in baselineFindings) finding.key,
    for (final Finding finding in baselineFindings) finding.fingerprint,
  };
  if (options.target == 'stats') {
    final int matched = existing.intersection(current).length;
    stdout.writeln(
      jsonEncode(<String, Object>{
        'version': 1,
        'command': 'baseline stats',
        'entries': existing.length,
        'matched': matched,
        'stale': existing.difference(current).length,
        'current_findings': baselineFindings.length,
      }),
    );
    return 0;
  }
  final Iterable<Finding> findings = options.target == 'prune'
      ? baselineFindings.where(
          (Finding finding) =>
              existing.contains(finding.key) ||
              existing.contains(finding.fingerprint),
        )
      : baselineFindings;
  BaselineCodec.write(output, findings);
  stdout.writeln(
    options.target == 'prune'
        ? 'pruned baseline ${output.path}'
        : options.target == 'update'
        ? 'updated baseline ${output.path}'
        : 'wrote baseline ${output.path}',
  );
  return 0;
}

Iterable<Finding> _nimBaselineGenericFindings(AnalysisRun run) sync* {
  for (final SourceFile file in run.files) {
    if (file.language != 'nim') continue;
    final List<String> lines = run.sources[file.relativePath]!.split('\n');
    for (var index = 0; index < lines.length; index++) {
      final String declaration = lines[index].trim();
      if (declaration.startsWith('import ') ||
          declaration.startsWith('from ')) {
        continue;
      }
      final int open = declaration.indexOf('[');
      final int close = declaration.indexOf(']', open + 1);
      if (open <= 0 || close <= open) continue;
      final String usage = declaration.substring(close + 1);
      final Set<String> parameters = declaration
          .substring(open + 1, close)
          .split(',')
          .map((String value) => value.trim().split(':').first.trim())
          .where((String value) => RegExp(r'^[A-Za-z_]\w*$').hasMatch(value))
          .toSet();
      for (final String parameter in parameters) {
        if (RegExp('\\b${RegExp.escape(parameter)}\\b').hasMatch(usage)) {
          continue;
        }
        yield Finding(
          code: 'unused-generic-parameter',
          severity: RuleSeverity.warn,
          path: file.relativePath,
          line: index + 1,
          endLine: index + 1,
          message:
              "generic parameter '$parameter' is not used by type ${declaration.substring(0, open).trim()}",
          confidence: 'high',
          why:
              'An unused type parameter adds a distinct type dimension without changing stored data or behavior.',
          suggestion:
              'Remove the parameter unless phantom typing is an intentional, documented constraint.',
          snippet: declaration,
        );
      }
    }
  }
}
