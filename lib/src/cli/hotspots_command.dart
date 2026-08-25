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
    stdout.write(
      renderHotspotsText(limited, color: stdout.supportsAnsiEscapes),
    );
  }
  return 0;
}

/// Renders hotspots for an interactive terminal or stable plain-text consumer.
String renderHotspotsText(List<Hotspot> hotspots, {required bool color}) {
  final _HotspotPalette palette = _HotspotPalette(color);
  final StringBuffer output = StringBuffer()
    ..writeln('${palette.accent('Code Buster hotspots')}: ${hotspots.length}');
  if (hotspots.isEmpty) {
    output.writeln(
      palette.muted('No Git history available for discovered files.'),
    );
  }
  for (final Hotspot item in hotspots) {
    output.writeln(
      '${palette.path(item.path)} — '
      '${palette.muted('risk')} ${palette.warning(item.risk.toStringAsFixed(1))}, '
      '${palette.muted('churn')} ${item.churn}, '
      '${palette.muted('commits')} ${item.commits} '
      '(${palette.added('+${item.added}')}/${palette.deleted('-${item.deleted}')})',
    );
  }
  return output.toString();
}

final class _HotspotPalette {
  const _HotspotPalette(this.enabled);

  final bool enabled;

  String accent(String value) => _wrap(value, '1;36');
  String path(String value) => _wrap(value, '36');
  String warning(String value) => _wrap(value, '33');
  String added(String value) => _wrap(value, '32');
  String deleted(String value) => _wrap(value, '31');
  String muted(String value) => _wrap(value, '2');

  String _wrap(String value, String code) =>
      enabled ? '\u001b[${code}m$value\u001b[0m' : value;
}
