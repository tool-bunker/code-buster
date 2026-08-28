// Format selection and shared encoding utilities belong at the reporting boundary rather than inside commands.

import 'dart:convert';

import '../catalog/rule_catalog.dart';
import '../core/models.dart';
import '../core/processing_diagnostic.dart';
import '../core/run_manifest.dart';
import '../core/schema_versions.dart';
import 'markdown_reporter.dart';
import 'report_model.dart';
import 'text_reporter.dart';

/// Supported Code Buster finding report encodings.
enum ReportFormat {
  /// Human-readable terminal output.
  text,

  /// One JSON document containing all findings.
  json,

  /// One JSON finding per line.
  ndjson,

  /// Markdown review table.
  markdown,

  /// SARIF 2.1.0 output for code-scanning integrations.
  sarif,

  /// Mermaid dependency or architecture graph output.
  mermaid,

  /// JUnit XML findings-as-failures output.
  junit;

  /// Parses a documented CLI format value.
  static ReportFormat parse(String value) => switch (value.toLowerCase()) {
    'text' => ReportFormat.text,
    'json' => ReportFormat.json,
    'ndjson' => ReportFormat.ndjson,
    'markdown' => ReportFormat.markdown,
    'sarif' => ReportFormat.sarif,
    'mermaid' => ReportFormat.mermaid,
    'junit' => ReportFormat.junit,
    _ => throw FormatException('Unknown Code Buster report format: $value'),
  };
}

/// Renders Code Buster findings in human and machine-readable formats.
final class FindingReporter {
  /// Renders [findings] for [command] over [files] under [root].
  String render({
    required ReportFormat format,
    required String command,
    required String root,
    required int files,
    required Iterable<Finding> findings,
    Map<String, Map<String, int>> languageSummary =
        const <String, Map<String, int>>{},
    Map<String, int> advisorySummary = const <String, int>{},
    int? actionableFindingCount,
    Map<String, int> coverage = const <String, int>{},
    RunManifest? manifest,
    Iterable<ProcessingDiagnostic> diagnostics = const <ProcessingDiagnostic>[],
    bool verbose = false,
    bool color = false,
  }) {
    final List<Finding> items = findings.map(_enriched).toList(growable: false);
    final ReportModel report = ReportModel(
      command: command,
      root: root,
      files: files,
      findings: items,
      languageSummary: languageSummary,
      coverage: coverage,
      advisorySummary: advisorySummary,
      actionableFindingCount: actionableFindingCount ?? items.length,
      manifest: manifest,
      diagnostics: diagnostics,
      verbose: verbose,
    );
    return switch (format) {
      ReportFormat.text => TextReporter().render(report, color: color),
      ReportFormat.json => jsonEncode(_envelope(report)),
      ReportFormat.ndjson => <String>[
        jsonEncode(<String, Object>{
          'schemaVersion': reportSchemaVersion,
          'recordType': 'summary',
          'command': report.command,
          'root': report.root,
          'files': report.files,
          'actionableFindingCount': report.actionableFindingCount,
          'detailedFindingCount': report.findings.length,
          'advisorySummary': <String, Object>{
            'total': report.advisoryFindingCount,
            'groups': report.advisorySummary,
          },
        }),
        for (final Finding finding in report.findings)
          jsonEncode(<String, Object>{
            'schemaVersion': reportSchemaVersion,
            'recordType': 'finding',
            ..._findingJson(finding),
          }),
        for (final ProcessingDiagnostic diagnostic in report.diagnostics)
          jsonEncode(<String, Object?>{
            'schemaVersion': reportSchemaVersion,
            'recordType': 'processingDiagnostic',
            ...diagnostic.toJson(),
          }),
      ].join('\n'),
      ReportFormat.markdown => MarkdownReporter().render(report),
      ReportFormat.sarif => jsonEncode(_sarif(report.findings)),
      ReportFormat.mermaid => throw const FormatException(
        'Mermaid output is only supported by graph commands',
      ),
      ReportFormat.junit => _junit(report.findings),
    };
  }

  Map<String, Object> _envelope(ReportModel report) => <String, Object>{
    'schemaVersion': reportSchemaVersion,
    'version': 1,
    'command': report.command,
    'root': report.root,
    'files': report.files,
    if (report.languageSummary.isNotEmpty)
      'languages': <Map<String, Object>>[
        for (final String language
            in report.languageSummary.keys.toList()..sort())
          <String, Object>{
            'language': language,
            'files': report.languageSummary[language]!['files']!,
            'findings': report.languageSummary[language]!['findings']!,
          },
      ],
    if (report.coverage.isNotEmpty) 'coverage': report.coverage,
    'actionableFindingCount': report.actionableFindingCount,
    'detailedFindingCount': report.findings.length,
    'advisorySummary': <String, Object>{
      'total': report.advisoryFindingCount,
      'groups': <String, int>{
        for (final String group in report.advisorySummary.keys.toList()..sort())
          group: report.advisorySummary[group]!,
      },
    },
    if (report.diagnostics.isNotEmpty)
      'processingDiagnostics': report.diagnostics
          .map((ProcessingDiagnostic diagnostic) => diagnostic.toJson())
          .toList(growable: false),
    if (report.manifest != null)
      'manifest': report.manifest!.toJson(
        includeFiles: report.verbose,
        includeOperational: report.verbose,
      ),
    'findings': report.findings.map(_findingJson).toList(growable: false),
  };

  Finding _enriched(Finding finding) => Finding(
    code: finding.code,
    severity: finding.severity,
    path: finding.path,
    line: finding.line,
    endLine: finding.endLine,
    message: finding.message,
    confidence: finding.confidence.isEmpty
        ? finding.severity == RuleSeverity.error
              ? 'high'
              : 'medium'
        : finding.confidence,
    why: finding.why.isNotEmpty
        ? finding.why
        : switch (finding.code) {
            'duplicate-block' =>
              'The same normalized code block appears in more than one location.',
            'complex-function' =>
              'The function exceeds configured complexity thresholds.',
            'feature-flag' => 'A feature/config flag reference was found.',
            'dead-file' || 'dead-export' =>
              'The symbol or file was not reached by the heuristic dependency graph.',
            'long-line' => 'A line exceeds the recommended style length.',
            'tab-indent' => 'A line contains a tab character.',
            'trailing-whitespace' => 'A line has trailing whitespace.',
            'nim-std-import' =>
              'A Nim standard-library import does not use the std/ prefix.',
            'nim-prefer-let' => 'A Nim variable declaration may be immutable.',
            _ =>
              'This finding was produced by a Code Buster heuristic analyzer.',
          },
    suggestion: finding.suggestion.isNotEmpty
        ? finding.suggestion
        : switch (finding.code) {
            'duplicate-block' =>
              'Extract shared logic or raise min_duplication_lines if intentional.',
            'complex-function' =>
              'Split branches into smaller helpers or simplify control flow.',
            'feature-flag' => 'Review ownership and lifecycle for this flag.',
            'dead-file' || 'dead-export' =>
              'Remove it or add an entry point/reference if it is loaded dynamically.',
            _ =>
              'Review the finding and update code or configuration as appropriate.',
          },
    relatedFiles: finding.relatedFiles,
    snippet: finding.snippet,
    codeFlow: finding.codeFlow,
  );

  Map<String, Object> _findingJson(Finding finding) {
    final SecurityFindingKind securityKind =
        RuleCatalog.lookup(finding.code)?.effectiveSecurityKind ??
        SecurityFindingKind.none;
    return <String, Object>{
      'code': finding.code,
      if (securityKind != SecurityFindingKind.none)
        'security_kind': securityKind.name,
      'severity': finding.severity.configValue,
      'path': finding.path,
      'line': finding.line,
      'end_line': finding.endLine,
      'message': finding.message,
      'confidence': finding.confidence,
      'why': finding.why,
      'suggestion': finding.suggestion,
      'related_files': finding.relatedFiles,
      'snippet': finding.snippet,
      if (finding.codeFlow.isNotEmpty)
        'code_flow': finding.codeFlow
            .map((CodeFlowStep step) => step.toJson())
            .toList(growable: false),
    };
  }

  Map<String, Object> _sarif(List<Finding> findings) {
    final Map<String, Finding> firstByCode = <String, Finding>{};
    for (final Finding finding in findings) {
      firstByCode.putIfAbsent(finding.code, () => finding);
    }
    return <String, Object>{
      r'$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
      'version': '2.1.0',
      'runs': <Object>[
        <String, Object>{
          'properties': <String, Object>{
            'codeBusterReportSchemaVersion': reportSchemaVersion,
          },
          'tool': <String, Object>{
            'driver': <String, Object>{
              'name': 'code-buster',
              'version': '0.3.0',
              'rules': firstByCode.entries
                  .map(
                    (MapEntry<String, Finding> entry) => <String, Object>{
                      'id': entry.key,
                      'name': entry.key,
                      'shortDescription': <String, String>{'text': entry.key},
                      'fullDescription': <String, String>{
                        'text': _ruleWhy(entry.key),
                      },
                      'help': <String, String>{
                        'text': _ruleSuggestion(entry.key),
                      },
                    },
                  )
                  .toList(growable: false),
            },
          },
          'results': findings
              .map(
                (Finding finding) => <String, Object>{
                  'ruleId': finding.code,
                  'level': switch (finding.severity) {
                    RuleSeverity.error => 'error',
                    RuleSeverity.warn => 'warning',
                    RuleSeverity.info => 'note',
                  },
                  'message': <String, String>{'text': finding.message},
                  'locations': <Object>[
                    <String, Object>{
                      'physicalLocation': <String, Object>{
                        'artifactLocation': <String, String>{
                          'uri': finding.path,
                        },
                        'region': <String, int>{
                          'startLine': finding.line,
                          'endLine': finding.endLine,
                        },
                      },
                    },
                  ],
                  if (finding.codeFlow.isNotEmpty)
                    'codeFlows': <Object>[
                      <String, Object>{
                        'threadFlows': <Object>[
                          <String, Object>{
                            'locations': finding.codeFlow
                                .map(
                                  (CodeFlowStep step) => <String, Object>{
                                    'location': <String, Object>{
                                      'message': <String, String>{
                                        'text': step.message,
                                      },
                                      'physicalLocation': <String, Object>{
                                        'artifactLocation': <String, String>{
                                          'uri': step.path,
                                        },
                                        'region': <String, int>{
                                          'startLine': step.line,
                                        },
                                      },
                                    },
                                  },
                                )
                                .toList(growable: false),
                          },
                        ],
                      },
                    ],
                },
              )
              .toList(growable: false),
        },
      ],
    };
  }

  String _junit(List<Finding> findings) {
    final StringBuffer output = StringBuffer(
      '<testsuite name="code-buster" tests="${findings.length}" failures="${findings.length}">',
    );
    for (final Finding finding in findings) {
      output.write(
        '\n<testcase classname="${_xml(finding.path)}" name="${_xml(finding.code)}">',
      );
      output.write('\n<failure message="${_xml(finding.message)}">');
      output.write(
        _xml(
          '${finding.severity.configValue} ${_location(finding)} ${finding.message}',
        ),
      );
      output.write('</failure>\n</testcase>');
    }
    output.write('\n</testsuite>');
    return output.toString();
  }

  String _ruleWhy(String code) => switch (code) {
    'duplicate-block' =>
      'The same normalized code block appears in more than one location.',
    'complex-function' =>
      'The function exceeds configured complexity thresholds.',
    'feature-flag' => 'A feature/config flag reference was found.',
    'dead-file' || 'dead-export' =>
      'The symbol or file was not reached by the heuristic dependency graph.',
    'long-line' => 'A line exceeds the recommended style length.',
    'tab-indent' => 'A line contains a tab character.',
    'trailing-whitespace' => 'A line has trailing whitespace.',
    'nim-std-import' =>
      'A Nim standard-library import does not use the std/ prefix.',
    'nim-prefer-let' => 'A Nim variable declaration may be immutable.',
    _ => 'This finding was produced by a Code Buster heuristic analyzer.',
  };

  String _ruleSuggestion(String code) => switch (code) {
    'duplicate-block' =>
      'Extract shared logic or raise min_duplication_lines if intentional.',
    'complex-function' =>
      'Split branches into smaller helpers or simplify control flow.',
    'feature-flag' => 'Review ownership and lifecycle for this flag.',
    'dead-file' || 'dead-export' =>
      'Remove it or add an entry point/reference if it is loaded dynamically.',
    'long-line' => 'Wrap the expression or call across multiple lines.',
    'tab-indent' => 'Replace tabs with spaces.',
    'trailing-whitespace' => 'Trim trailing whitespace.',
    'nim-std-import' =>
      'Use std/module or std/[a, b] for standard-library imports.',
    'nim-prefer-let' => 'Use let unless the value is reassigned or mutated.',
    _ => 'Review the finding and update code or configuration as appropriate.',
  };

  String _location(Finding finding) => finding.endLine > finding.line
      ? '${finding.path}:${finding.line}-${finding.endLine}'
      : '${finding.path}:${finding.line}';

  String _xml(String value) => value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;');
}
