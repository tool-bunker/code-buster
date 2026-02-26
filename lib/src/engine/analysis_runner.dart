// A command asks for one run; this coordinator turns options into a complete result while preserving diagnostics and timing evidence.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../cli/cli_contract.dart';
import '../controls/finding_controls.dart';
import '../core/models.dart';
import '../core/processing_diagnostic.dart';
import '../core/rule_policy.dart';
import '../core/run_manifest.dart';
import '../discovery/discovery.dart';
import '../graph/graph.dart';
import '../ingestion/sarif_ingestion.dart';
import '../plugins/language_plugin.dart';
import 'analysis_pipeline.dart';
import 'rule_execution.dart';

final LanguagePluginRegistry _languagePlugins =
    LanguagePluginRegistry.standard();

/// Materialized inputs and findings for one Code Buster command invocation.
final class AnalysisRun {
  /// Creates one completed analysis invocation.
  const AnalysisRun({
    required this.config,
    required this.files,
    required this.sources,
    required this.graph,
    required this.findings,
    this.coverage = const <String, int>{},
    this.diagnostics = const <ProcessingDiagnostic>[],
    this.manifest,
  });

  /// Effective project configuration.
  final AnalysisConfig config;

  /// Discovered Dart source files.
  final List<SourceFile> files;

  /// Project-relative source content.
  final Map<String, String> sources;

  /// Resolved local Dart dependency graph.
  final DependencyGraph graph;

  /// Filtered command findings.
  final List<Finding> findings;

  /// Findings from active report and count rules.
  List<Finding> get activeFindings => List<Finding>.unmodifiable(
    findings.where(
      (Finding finding) =>
          RulePolicy(config).modeFor(finding.code) != RuleMode.off,
    ),
  );

  /// Findings shown individually and included in default quality gates.
  List<Finding> get actionableFindings => List<Finding>.unmodifiable(
    findings.where(
      (Finding finding) =>
          RulePolicy(config).modeFor(finding.code) == RuleMode.report,
    ),
  );

  /// Findings analyzed but summarized by count in default output.
  List<Finding> get advisoryFindings => List<Finding>.unmodifiable(
    findings.where(
      (Finding finding) =>
          RulePolicy(config).modeFor(finding.code) == RuleMode.count,
    ),
  );

  /// Advisory totals grouped by the rule's semantic activation group.
  Map<String, int> get advisorySummary {
    final Map<String, int> result = <String, int>{};
    for (final Finding finding in advisoryFindings) {
      final String group = RulePolicy.taxonomyGroupFor(finding.code);
      result[group] = (result[group] ?? 0) + 1;
    }
    return Map<String, int>.unmodifiable(result);
  }

  /// Selected and excluded source accounting.
  final Map<String, int> coverage;

  /// Processing problems kept separate from source-code findings.
  final List<ProcessingDiagnostic> diagnostics;

  /// Reproducibility evidence for runner-produced analyses.
  final RunManifest? manifest;

  /// Per-language file and finding totals for report summaries.
  Map<String, Map<String, int>> get languageSummary =>
      languageSummaryFor(findings);

  /// Per-language totals for the provided finding detail selection.
  Map<String, Map<String, int>> languageSummaryFor(
    Iterable<Finding> selectedFindings,
  ) {
    final Map<String, String> languageByPath = <String, String>{
      for (final SourceFile file in files) file.relativePath: file.language,
    };
    final Map<String, Map<String, int>> result = <String, Map<String, int>>{};
    for (final SourceFile file in files) {
      result.putIfAbsent(
        file.language,
        () => <String, int>{'files': 0, 'findings': 0},
      )['files'] = result[file.language]!['files']! + 1;
    }
    for (final Finding finding in selectedFindings) {
      final String? language = languageByPath[finding.path];
      if (language != null) {
        result[language]!['findings'] = result[language]!['findings']! + 1;
      }
    }
    return Map<String, Map<String, int>>.unmodifiable(result);
  }
}

/// Coordinates configured Dart discovery, graph construction, rules, and filters.
final class AnalysisRunner {
  /// Creates a runner using the built-in offline pipeline.
  const AnalysisRunner();

  /// Runs one finding-producing [CodeBusterCliOptions.command] over the project.
  AnalysisRun run(CodeBusterCliOptions options, {CodeBusterCommand? command}) {
    final Stopwatch stopwatch = Stopwatch()..start();
    final PreparedAnalysis prepared = AnalysisPreparationStage().prepare(
      options,
    );
    final AnalysisConfig config = prepared.config;
    final List<SourceFile> files = prepared.files;
    final Map<String, String> sources = prepared.sources;
    final IndexedAnalysis indexed = LanguageIndexStage(
      _languagePlugins,
    ).build(prepared);
    final SarifIngestionResult ingestion = const SarifIngestion().read(
      options.ingestSarif,
      config.root,
    );
    final List<ProcessingDiagnostic> diagnostics = <ProcessingDiagnostic>[
      ...prepared.diagnostics,
      for (final LanguageAnalysis language in indexed.languages.values)
        ...language.diagnostics,
      ...ingestion.diagnostics,
    ];
    final AnalysisCacheStage cache = AnalysisCacheStage();
    final DependencyGraph graph = cache.graph(
      prepared,
      () => GraphConstructionStage(_languagePlugins).build(indexed),
    );
    final GraphAnalysis graphAnalysis = GraphAnalysis(graph);
    final CodeBusterCommand effectiveCommand = command ?? options.command;
    final List<Finding> raw = cache.findings(
      prepared,
      effectiveCommand,
      () => RuleExecutionStage(
        languagePlugins: _languagePlugins,
      ).execute(effectiveCommand, indexed, graphAnalysis),
    );
    final Set<String> baseline = options.baseline.isEmpty
        ? const <String>{}
        : BaselineCodec.read(File(options.baseline));
    final List<Finding> controlledFindings = const FindingControlStage().apply(
      prepared: prepared,
      findings: <Finding>[...raw, ...ingestion.findings],
      baseline: baseline,
      only: options.only,
    );
    final RulePolicy policy = RulePolicy(config);
    final List<Finding> findings = controlledFindings
        .where(
          (Finding finding) => policy.modeFor(finding.code) != RuleMode.off,
        )
        .toList(growable: false);
    stopwatch.stop();
    final List<String> selectedFiles =
        files
            .map((SourceFile file) => file.relativePath)
            .toList(growable: false)
          ..sort();
    final List<String> languages =
        files
            .map((SourceFile file) => file.language)
            .toSet()
            .toList(growable: false)
          ..sort();
    return AnalysisRun(
      config: config,
      files: List<SourceFile>.unmodifiable(files),
      sources: Map<String, String>.unmodifiable(sources),
      graph: graph,
      findings: List<Finding>.unmodifiable(findings),
      coverage: prepared.coverage,
      diagnostics: List<ProcessingDiagnostic>.unmodifiable(diagnostics),
      manifest: RunManifest(
        command: effectiveCommand.name,
        status: diagnostics.isEmpty
            ? RunStatus.complete
            : diagnostics.any(
                (ProcessingDiagnostic diagnostic) =>
                    diagnostic.severity == ProcessingDiagnosticSeverity.error,
              )
            ? RunStatus.failed
            : RunStatus.partial,
        root: config.root,
        gitRevision: _gitRevision(config.root),
        sourceHash: _sourceHash(sources),
        configHash: cache.cache.key(
          config: config,
          sources: const <String, String>{},
          kind: 'manifest-config',
        ),
        selectedFiles: List<String>.unmodifiable(selectedFiles),
        coverage: prepared.coverage,
        languages: List<String>.unmodifiable(languages),
        languageVersions: prepared.languageVersions,
        graphCacheHit: cache.graphCacheHit,
        findingsCacheHit: cache.findingsCacheHit,
        durationMilliseconds: stopwatch.elapsedMilliseconds,
      ),
    );
  }

  static String _sourceHash(Map<String, String> sources) {
    final StringBuffer material = StringBuffer();
    for (final String path in sources.keys.toList()..sort()) {
      material
        ..writeln(path)
        ..writeln(sha256.convert(utf8.encode(sources[path]!)));
    }
    return sha256.convert(utf8.encode(material.toString())).toString();
  }

  static String? _gitRevision(String root) {
    final ProcessResult result = Process.runSync('git', const <String>[
      'rev-parse',
      '--verify',
      'HEAD',
    ], workingDirectory: root);
    if (result.exitCode != 0) return null;
    final String revision = (result.stdout as String).trim();
    return revision.isEmpty ? null : revision;
  }
}
