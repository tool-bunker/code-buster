// Human terminal output prioritizes scanability, optional color, and concise evidence rather than machine-contract completeness.

import '../core/models.dart';
import 'report_model.dart';

/// Encodes a normalized report for interactive terminal use.
final class TextReporter {
  /// Renders [report], optionally applying ANSI styles.
  String render(ReportModel report, {required bool color}) {
    final _TerminalPalette palette = _TerminalPalette(color);
    final String actionable =
        '${report.actionableFindingCount} actionable findings';
    final StringBuffer output = StringBuffer(
      '${palette.accent(_title(report.command))}: ${report.files} files, '
      '${report.actionableFindingCount == 0 ? palette.success(actionable) : palette.error(actionable)}',
    );
    if (report.languageSummary.length > 1) {
      for (final String language in <String>[
        'nim',
        'dart',
        'wren',
        'typescript',
        'javascript',
        'python',
        'csharp',
        'cpp',
        'java',
        'lua',
      ]) {
        final Map<String, int>? totals = report.languageSummary[language];
        if (totals != null) {
          output.write(
            '\n  ${palette.muted(language.padRight(12))}${totals['files']} files, '
            '${totals['findings']} findings',
          );
        }
      }
    }
    if (report.coverage.isNotEmpty) {
      final List<String> keys = report.coverage.keys.toList()..sort();
      output.write(
        '\n  ${palette.muted('coverage'.padRight(12))}'
        '${keys.map((String key) => '$key=${report.coverage[key]}').join(' ')}',
      );
    }
    if (report.advisoryFindingCount > 0) {
      output.write(
        '\n  ${palette.warning('advisory'.padRight(12))}'
        '${palette.warning('${report.advisoryFindingCount} findings')}',
      );
      for (final String group in report.advisorySummary.keys.toList()..sort()) {
        output.write(
          '\n    ${palette.group(group.padRight(16))}'
          '${report.advisorySummary[group]}',
        );
      }
      output.write(
        '\n  ${palette.muted('Run `cb review --advisory` for advisory details.')}',
      );
    }
    for (final Finding finding in report.findings) {
      final String location = finding.line == finding.endLine
          ? '${finding.path}:${finding.line}'
          : '${finding.path}:${finding.line}-${finding.endLine}';
      final String severity = switch (finding.severity) {
        RuleSeverity.error => palette.error(finding.severity.configValue),
        RuleSeverity.warn => palette.warning(finding.severity.configValue),
        RuleSeverity.info => palette.accent(finding.severity.configValue),
      };
      output.writeln();
      output.write(
        '$severity ${palette.accent(finding.code)} '
        '${palette.muted(location)} ${finding.message}',
      );
      if (report.verbose) {
        if (finding.why.isNotEmpty) {
          output.write('\n  ${palette.muted('why:')} ${finding.why}');
        }
        if (finding.confidence.isNotEmpty) {
          output.write(
            '\n  ${palette.muted('confidence:')} ${finding.confidence}',
          );
        }
        if (finding.relatedFiles.isNotEmpty) {
          output.write(
            '\n  ${palette.muted('related:')} ${finding.relatedFiles.join(', ')}',
          );
        }
        if (finding.suggestion.isNotEmpty) {
          output.write(
            '\n  ${palette.muted('suggestion:')} ${finding.suggestion}',
          );
        }
      }
    }
    return output.toString();
  }

  String _title(String command) => switch (command) {
    'dead' => 'Code Buster dead',
    'duplication' => 'Code Buster duplication',
    'flags' => 'Code Buster flags',
    'complexity' => 'Code Buster complexity',
    'structure' => 'Code Buster structure',
    _ => 'Code Buster summary',
  };
}

final class _TerminalPalette {
  const _TerminalPalette(this.enabled);

  final bool enabled;

  String accent(String value) => _wrap(value, '1;36');
  String success(String value) => _wrap(value, '32');
  String warning(String value) => _wrap(value, '33');
  String error(String value) => _wrap(value, '1;31');
  String group(String value) => _wrap(value, '35');
  String muted(String value) => _wrap(value, '2');

  String _wrap(String value, String code) =>
      enabled ? '\u001b[${code}m$value\u001b[0m' : value;
}
