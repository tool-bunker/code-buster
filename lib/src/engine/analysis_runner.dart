// A command asks for one run; this coordinator turns options into a complete result while preserving diagnostics and timing evidence.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../cache/analysis_cache.dart';
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
import 'analysis_execution_plan.dart';
import 'analysis_pipeline.dart';
import 'rule_execution.dart';

final LanguagePluginRegistry _languagePlugins =
    LanguagePluginRegistry.standard();

/// Materialized inputs and findings for one Code Buster command invocation.
final class AnalysisRun {
  /// Creates one completed analysis invocation.
  AnalysisRun({
    required this.config,
    required this.files,
    required this.sources,
    required this.graph,
    required this.findings,
    this.coverage = const <String, int>{},
    this.diagnostics = const <ProcessingDiagnostic>[],
    this.manifest,
  }) {
    final RulePolicy policy = RulePolicy(config);
    final List<Finding> active = <Finding>[];
    final List<Finding> actionable = <Finding>[];
    final List<Finding> advisory = <Finding>[];
    final Map<String, int> advisoryGroups = <String, int>{};
    for (final Finding finding in findings) {
      switch (policy.modeFor(finding.code)) {
        case RuleMode.off:
          break;
        case RuleMode.report:
          active.add(finding);
          actionable.add(finding);
          break;
        case RuleMode.count:
          active.add(finding);
          advisory.add(finding);
          final String group = RulePolicy.taxonomyGroupFor(finding.code);
          advisoryGroups[group] = (advisoryGroups[group] ?? 0) + 1;
          break;
      }
    }
    activeFindings = List<Finding>.unmodifiable(active);
    actionableFindings = List<Finding>.unmodifiable(actionable);
    advisoryFindings = List<Finding>.unmodifiable(advisory);
    advisorySummary = Map<String, int>.unmodifiable(advisoryGroups);
    _languageByPath = <String, String>{
      for (final SourceFile file in files) file.relativePath: file.language,
    };
    final Map<String, int> fileCounts = <String, int>{};
    for (final SourceFile file in files) {
      fileCounts[file.language] = (fileCounts[file.language] ?? 0) + 1;
    }
    _languageFileCounts = Map<String, int>.unmodifiable(fileCounts);
  }

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
  late final List<Finding> activeFindings;

  /// Findings shown individually and included in default quality gates.
  late final List<Finding> actionableFindings;

  /// Findings analyzed but summarized by count in default output.
  late final List<Finding> advisoryFindings;

  /// Advisory totals grouped by the rule's semantic activation group.
  late final Map<String, int> advisorySummary;

  late final Map<String, String> _languageByPath;

  late final Map<String, int> _languageFileCounts;

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
    final Map<String, Map<String, int>> result = <String, Map<String, int>>{
      for (final MapEntry<String, int> entry in _languageFileCounts.entries)
        entry.key: <String, int>{'files': entry.value, 'findings': 0},
    };
    for (final Finding finding in selectedFindings) {
      final String? language = _languageByPath[finding.path];
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
    final Map<String, int> stageDurations = <String, int>{};
    final PreparedAnalysis prepared = _timed(
      stageDurations,
      'preparation',
      () => AnalysisPreparationStage().prepare(options),
    );
    final AnalysisConfig config = prepared.config;
    final CodeBusterCommand effectiveCommand = command ?? options.command;
    final AnalysisExecutionPlan executionPlan = AnalysisExecutionPlan(
      command: effectiveCommand,
      config: config,
      only: options.only,
    );
    final List<SourceFile> files = prepared.files;
    final Map<String, String> sources = prepared.sources;
    IndexedAnalysis? indexed;
    final LanguageIndexStage languageIndex = LanguageIndexStage(
      _languagePlugins,
    );
    IndexedAnalysis resolveIndexed() {
      final IndexedAnalysis? existing = indexed;
      if (existing != null) return existing;
      final IndexedAnalysis result = _timed(
        stageDurations,
        'languageIndex',
        () => languageIndex.build(prepared, plan: executionPlan),
      );
      for (final MapEntry<String, int> timing
          in languageIndex.timings.entries) {
        stageDurations['languageIndex.${timing.key}'] = timing.value;
      }
      indexed = result;
      return result;
    }

    final AnalysisCacheStage cache = AnalysisCacheStage(
      enabled: options.cacheEnabled,
      cache: PersistentAnalysisCache(
        directory: options.cacheDirectory.isEmpty
            ? null
            : Directory(options.cacheDirectory).absolute.path,
      ),
    );
    DependencyGraph? resolvedGraph;
    DependencyGraph resolveGraph() {
      final DependencyGraph? existing = resolvedGraph;
      if (existing != null) return existing;
      final DependencyGraph result = _timed(
        stageDurations,
        'graph',
        () => cache.graph(
          prepared,
          () =>
              GraphConstructionStage(_languagePlugins).build(resolveIndexed()),
        ),
      );
      resolvedGraph = result;
      return result;
    }

    final SarifIngestionResult ingestion = _timed(
      stageDurations,
      'sarifIngestion',
      () => const SarifIngestion().read(options.ingestSarif, config.root),
    );
    RuleExecutionStage? ruleExecution;
    List<Finding> analyzeRules() {
      final RuleExecutionStage execution = RuleExecutionStage(
        languagePlugins: _languagePlugins,
        cacheFamily: options.only.isEmpty
            ? (
                String family,
                Map<String, String>? sourceInputs,
                List<Finding> Function() analyze,
              ) => cache.findingFamily(
                prepared,
                '${effectiveCommand.name}.$family',
                analyze,
                sourceInputs: sourceInputs,
              )
            : null,
      );
      ruleExecution = execution;
      return execution.execute(
        effectiveCommand,
        resolveIndexed(),
        GraphAnalysis(resolveGraph()),
        only: options.only,
      );
    }

    final List<Finding> raw = _timed(
      stageDurations,
      'rules',
      () => options.only.isEmpty
          ? cache.findings(
              prepared,
              effectiveCommand,
              analyzeRules,
              cacheable: () => indexed!.languages.values.every(
                (LanguageAnalysis language) => language.diagnostics.isEmpty,
              ),
            )
          : analyzeRules(),
    );
    final DependencyGraph graph = resolveGraph();
    final RuleExecutionStage? completedRuleExecution = ruleExecution;
    if (completedRuleExecution != null) {
      for (final MapEntry<String, int> timing
          in completedRuleExecution.familyTimings.entries) {
        stageDurations['rules.${timing.key}'] = timing.value;
      }
    }
    final List<ProcessingDiagnostic> diagnostics = <ProcessingDiagnostic>[
      ...prepared.diagnostics,
      if (indexed case final IndexedAnalysis completedIndex)
        for (final LanguageAnalysis language in completedIndex.languages.values)
          ...language.diagnostics,
      ...ingestion.diagnostics,
    ];
    final Set<String> baseline = options.baseline.isEmpty
        ? const <String>{}
        : BaselineCodec.read(File(options.baseline));
    final List<Finding> controlledFindings = _timed(
      stageDurations,
      'controls',
      () => const FindingControlStage().apply(
        prepared: prepared,
        findings: <Finding>[...raw, ...ingestion.findings],
        baseline: baseline,
        only: options.only,
      ),
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
        stageDurationsMilliseconds: Map<String, int>.unmodifiable(
          stageDurations,
        ),
      ),
    );
  }

  static T _timed<T>(
    Map<String, int> durations,
    String name,
    T Function() operation,
  ) {
    final Stopwatch stopwatch = Stopwatch()..start();
    final T result = operation();
    durations[name] = stopwatch.elapsedMilliseconds;
    return result;
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
