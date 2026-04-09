// All encoders consume this normalized snapshot so text, JSON, SARIF, and JUnit cannot disagree about counts or visible findings.

import '../core/models.dart';
import '../core/processing_diagnostic.dart';
import '../core/run_manifest.dart';

/// Immutable normalized input shared by every report encoder.
final class ReportModel {
  ReportModel({
    required this.command,
    required this.root,
    required this.files,
    required Iterable<Finding> findings,
    required this.languageSummary,
    required this.coverage,
    required this.advisorySummary,
    required this.actionableFindingCount,
    required this.manifest,
    required Iterable<ProcessingDiagnostic> diagnostics,
    required this.verbose,
  }) : findings = List<Finding>.unmodifiable(findings),
       diagnostics = List<ProcessingDiagnostic>.unmodifiable(diagnostics);

  final String command;

  final String root;

  final int files;

  final List<Finding> findings;

  final Map<String, Map<String, int>> languageSummary;

  final Map<String, int> coverage;

  final Map<String, int> advisorySummary;

  final int actionableFindingCount;

  final RunManifest? manifest;

  final List<ProcessingDiagnostic> diagnostics;

  final bool verbose;

  int get advisoryFindingCount => advisorySummary.values.fold<int>(
    0,
    (int total, int count) => total + count,
  );
}
