// Markdown needs stable sections, links, and escaping that differ from both terminal output and machine formats.

import '../core/models.dart';
import 'report_model.dart';

/// Encodes a normalized report as a Markdown review table.
final class MarkdownReporter {
  /// Renders [report] as Markdown.
  String render(ReportModel report) {
    final StringBuffer output = StringBuffer(
      '# Code Buster Nim ${report.command}\n\n',
    );
    output.write(
      '- root: `${report.root}`\n'
      '- files: ${report.files}\n'
      '- findings: ${report.findings.length}\n',
    );
    if (report.findings.isEmpty) return output.toString().trimRight();
    output.write(
      '\n| severity | code | location | message |\n|---|---|---|---|\n',
    );
    for (final Finding finding in report.findings) {
      final String location = finding.endLine > finding.line
          ? '${finding.path}:${finding.line}-${finding.endLine}'
          : '${finding.path}:${finding.line}';
      output.write(
        '| ${finding.severity.configValue} | `${finding.code}` | '
        '`$location` | ${finding.message.replaceAll('|', r'\|')} |\n',
      );
    }
    return output.toString().trimRight();
  }
}
