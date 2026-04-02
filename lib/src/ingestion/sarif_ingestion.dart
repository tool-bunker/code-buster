// External scanners can contribute findings, but their paths and payloads must be validated before joining native results.

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;

import '../core/models.dart';
import '../core/processing_diagnostic.dart';

/// Immutable findings and diagnostics decoded from external SARIF.
final class SarifIngestionResult {
  /// Creates one ingestion result.
  const SarifIngestionResult({
    required this.findings,
    required this.diagnostics,
  });

  /// Attributed external findings.
  final List<Finding> findings;

  /// Recoverable report and location problems.
  final List<ProcessingDiagnostic> diagnostics;
}

/// Reads SARIF without executing tools or trusting report paths.
final class SarifIngestion {
  /// Creates a stateless read-only decoder.
  const SarifIngestion();

  /// Decodes [reports] and rejects locations outside [root].
  SarifIngestionResult read(Iterable<String> reports, String root) {
    final List<Finding> findings = <Finding>[];
    final List<ProcessingDiagnostic> diagnostics = <ProcessingDiagnostic>[];
    for (final String reportPath in reports) {
      try {
        final Object? decoded = jsonDecode(File(reportPath).readAsStringSync());
        if (decoded is! Map || decoded['runs'] is! List) {
          throw const FormatException('expected a SARIF runs array');
        }
        for (final Object? rawRun in decoded['runs'] as List<dynamic>) {
          if (rawRun is! Map) continue;
          final Map<Object?, Object?> run = rawRun;
          final String provider = _provider(run);
          final Object? rawResults = run['results'];
          if (rawResults is! List) continue;
          for (final Object? rawResult in rawResults) {
            if (rawResult is! Map) continue;
            final Finding? finding = _finding(rawResult, provider, root);
            if (finding != null) findings.add(finding);
          }
        }
      } on Object catch (error) {
        diagnostics.add(
          ProcessingDiagnostic(
            code: 'sarif-ingestion-failed',
            severity: ProcessingDiagnosticSeverity.warning,
            stage: 'ingestion',
            path: reportPath,
            message: '$error',
          ),
        );
      }
    }
    findings.sort((Finding left, Finding right) {
      final int pathOrder = left.path.compareTo(right.path);
      if (pathOrder != 0) return pathOrder;
      final int lineOrder = left.line.compareTo(right.line);
      return lineOrder != 0 ? lineOrder : left.code.compareTo(right.code);
    });
    return SarifIngestionResult(
      findings: List<Finding>.unmodifiable(findings),
      diagnostics: List<ProcessingDiagnostic>.unmodifiable(diagnostics),
    );
  }

  String _provider(Map<Object?, Object?> run) {
    final Object? tool = run['tool'];
    final Object? driver = tool is Map ? tool['driver'] : null;
    final Object? name = driver is Map ? driver['name'] : null;
    return name is String && name.trim().isNotEmpty
        ? _slug(name)
        : 'external-sarif';
  }

  Finding? _finding(
    Map<Object?, Object?> result,
    String provider,
    String root,
  ) {
    final Object? rule = result['ruleId'];
    final Object? locations = result['locations'];
    if (rule is! String || locations is! List || locations.isEmpty) return null;
    final Object? first = locations.first;
    final Object? physical = first is Map ? first['physicalLocation'] : null;
    final Object? artifact = physical is Map
        ? physical['artifactLocation']
        : null;
    final Object? uri = artifact is Map ? artifact['uri'] : null;
    if (uri is! String || uri.isEmpty || Uri.tryParse(uri)?.hasScheme == true) {
      return null;
    }
    final String relative = path.normalize(uri.replaceAll('\\', '/'));
    final String absolute = path.normalize(path.absolute(root, relative));
    if (!path.isWithin(path.normalize(path.absolute(root)), absolute)) {
      return null;
    }
    final Object? region = physical is Map ? physical['region'] : null;
    final int line = region is Map && region['startLine'] is int
        ? region['startLine'] as int
        : 1;
    final int endLine = region is Map && region['endLine'] is int
        ? region['endLine'] as int
        : line;
    final Object? message = result['message'];
    final Object? text = message is Map ? message['text'] : null;
    return Finding(
      code: 'external:$provider:$rule',
      severity: switch (result['level']) {
        'error' => RuleSeverity.error,
        'warning' => RuleSeverity.warn,
        _ => RuleSeverity.info,
      },
      path: path.posix.normalize(relative),
      line: line,
      endLine: endLine,
      message: text is String ? text : 'external SARIF finding',
      confidence: 'external',
      why: 'Imported read-only from the attributed `$provider` SARIF report.',
      suggestion: 'Review remediation guidance from the originating analyzer.',
    );
  }

  String _slug(String value) => value
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '-')
      .replaceAll(RegExp(r'^-+|-+$'), '');
}
