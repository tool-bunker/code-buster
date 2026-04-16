// Churn is evidence from Git history rather than source semantics, and this command turns that evidence into hotspot findings.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Reports source churn hotspots from local Git history.
final class HotspotsCommand implements CliCommandHandler {
  /// Creates the hotspots command.
  const HotspotsCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.hotspots,
  };

  @override
  int execute(CodeBusterCliOptions options) => _hotspots(options);
}

int _hotspots(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(options);
  if (run.files.isEmpty && !options.allowEmpty) {
    stderr.writeln('no source files found (use --allow-empty to allow this)');
    return 1;
  }
  final List<Hotspot> hotspots = HotspotAnalysis.fromGit(
    root: run.config.root,
    allowed: run.sources.keys.toSet(),
  );
  final List<Hotspot> limited = options.top > 0 && hotspots.length > options.top
      ? hotspots.sublist(0, options.top)
      : hotspots;
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'version': 1,
        'command': 'hotspots',
        'root': run.config.root,
        'hotspots': limited
            .map(
              (Hotspot item) => <String, Object>{
                'path': item.path,
                'commits': item.commits,
                'added': item.added,
                'deleted': item.deleted,
                'churn': item.churn,
                'risk': item.risk,
              },
            )
            .toList(growable: false),
      }),
    );
  } else {
    stdout.writeln('Code Buster hotspots: ${limited.length}');
    if (limited.isEmpty) {
      stdout.writeln('No Git history available for discovered files.');
    }
    for (final Hotspot item in limited) {
      stdout.writeln(
        '${item.path} — risk ${item.risk.toStringAsFixed(1)}, churn ${item.churn}, commits ${item.commits} (+${item.added}/-${item.deleted})',
      );
    }
  }
  return 0;
}
