// Preparation, indexing, graph construction, and rule execution are separate stages so partial failures and cached work remain understandable.

import 'dart:convert';
import 'dart:io';

import '../cache/analysis_cache.dart';
import '../cli/cli_contract.dart';
import '../config/config.dart';
import '../config/repository_defaults.dart';
import '../controls/finding_controls.dart';
import '../core/models.dart';
import '../core/processing_diagnostic.dart';
import '../core/regexp_cache.dart';
import '../discovery/discovery.dart';
import '../discovery/language_versions.dart';
import '../graph/graph.dart';
import '../plugins/language_plugin.dart';
import '../plugins/languages.dart';

/// Immutable configuration and source inputs prepared for analysis stages.
final class PreparedAnalysis {
  const PreparedAnalysis({
    required this.root,
    required this.config,
    required this.files,
    required this.sources,
    required this.changedLineRanges,
    this.changedPaths = const <String>{},
    this.baseSources = const <String, String>{},
    this.auxiliaryFiles = const <String, String>{},
    this.coverage = const <String, int>{},
    this.diagnostics = const <ProcessingDiagnostic>[],
    this.languageVersions = const <String, String>{},
    this.generatedProvenance = const <GeneratedSourceProvenance>[],
  });

  final String root;

  final AnalysisConfig config;

  final List<SourceFile> files;

  final Map<String, String> sources;

  final Map<String, List<ChangedLineRange>> changedLineRanges;
  final Set<String> changedPaths;

  final Map<String, String> baseSources;
  final Map<String, String> auxiliaryFiles;

  final Map<String, int> coverage;

  final List<ProcessingDiagnostic> diagnostics;

  final Map<String, String> languageVersions;

  final List<GeneratedSourceProvenance> generatedProvenance;

  Map<String, String> sourcesFor(Set<String> languages) =>
      Map<String, String>.unmodifiable(<String, String>{
        for (final SourceFile file in files)
          if (languages.contains(file.language))
            file.relativePath: sources[file.relativePath]!,
      });
}

/// Loads and stores content-addressed graph and finding stage results.
final class AnalysisCacheStage {
  AnalysisCacheStage({PersistentAnalysisCache? cache, this.enabled = true})
    : cache = cache ?? const PersistentAnalysisCache();

  final PersistentAnalysisCache cache;
  final bool enabled;

  bool _graphCacheHit = false;
  bool get graphCacheHit => _graphCacheHit;

  bool _findingsCacheHit = false;
  bool get findingsCacheHit => _findingsCacheHit;

  DependencyGraph graph(
    PreparedAnalysis prepared,
    DependencyGraph Function() build,
  ) {
    if (!enabled) return build();
    final String key = cache.key(
      config: prepared.config,
      sources: prepared.sources,
      kind: 'graph',
    );
    final DependencyGraph? cached = cache.loadGraph(
      config: prepared.config,
      key: key,
    );
    if (cached != null) {
      _graphCacheHit = true;
      return cached;
    }
    final DependencyGraph result = build();
    cache.storeGraph(config: prepared.config, key: key, graph: result);
    return result;
  }

  List<Finding> findings(
    PreparedAnalysis prepared,
    CodeBusterCommand command,
    List<Finding> Function() analyze,
  ) {
    if (!enabled) return List<Finding>.unmodifiable(analyze());
    final Map<String, String> findingInputs = <String, String>{
      ...prepared.sources,
      for (final MapEntry<String, String> entry in prepared.baseSources.entries)
        '@base/${entry.key}': entry.value,
      for (final String changedPath in prepared.changedPaths)
        '@changed/$changedPath': '',
      for (final MapEntry<String, String> entry
          in prepared.auxiliaryFiles.entries)
        '@aux/${entry.key}': entry.value,
    };
    final String key = cache.key(
      config: prepared.config,
      sources: findingInputs,
      kind: 'findings:${command.name}',
    );
    final List<Finding>? cached = cache.loadFindings(
      config: prepared.config,
      key: key,
    );
    if (cached != null) {
      _findingsCacheHit = true;
      return List<Finding>.unmodifiable(cached);
    }
    final List<Finding> result = List<Finding>.unmodifiable(analyze());
    cache.storeFindings(config: prepared.config, key: key, findings: result);
    return result;
  }
}

/// Applies suppressions, severity overrides, baselines, and changed-line scope.
final class FindingControlStage {
  const FindingControlStage();

  List<Finding> apply({
    required PreparedAnalysis prepared,
    required Iterable<Finding> findings,
    required Set<String> baseline,
    required String only,
  }) {
    var controlled = FindingFilter().apply(
      config: prepared.config,
      findings: findings,
      sources: prepared.sources,
      baseline: baseline,
      only: only,
    );
    if (prepared.config.changedLines) {
      controlled = controlled
          .where(
            (Finding finding) =>
                _touchesChangedLine(finding, prepared.changedLineRanges),
          )
          .toList(growable: false);
    }
    return List<Finding>.unmodifiable(controlled);
  }

  bool _touchesChangedLine(
    Finding finding,
    Map<String, List<ChangedLineRange>> ranges,
  ) {
    final List<ChangedLineRange>? pathRanges = ranges[finding.path];
    if (pathRanges == null) return ranges.isEmpty;
    final int end = finding.endLine == 0 ? finding.line : finding.endLine;
    return pathRanges.any(
      (ChangedLineRange range) =>
          finding.line <= range.end && end >= range.start,
    );
  }
}

/// Immutable parse/index results produced once for each language plugin.
final class IndexedAnalysis {
  const IndexedAnalysis({required this.prepared, required this.languages});

  final PreparedAnalysis prepared;

  final Map<String, LanguageAnalysis> languages;

  LanguageAnalysis require(String language) {
    final LanguageAnalysis? analysis = languages[language];
    if (analysis != null) return analysis;
    throw StateError('No indexed analysis available for $language');
  }
}

/// Invokes every language plugin once over its discovered source set.
final class LanguageIndexStage {
  const LanguageIndexStage(this.plugins);

  final LanguagePluginRegistry plugins;

  IndexedAnalysis build(PreparedAnalysis prepared) => IndexedAnalysis(
    prepared: prepared,
    languages:
        Map<String, LanguageAnalysis>.unmodifiable(<String, LanguageAnalysis>{
          for (final LanguagePlugin plugin in plugins.plugins)
            plugin.id: plugin.analyze(
              prepared.sourcesFor(plugin.sourceLanguageIds),
              prepared.config,
            ),
        }),
  );
}

/// Builds one repository graph from indexed language results.
final class GraphConstructionStage {
  const GraphConstructionStage(this.plugins);

  final LanguagePluginRegistry plugins;

  DependencyGraph build(IndexedAnalysis indexed) {
    final Map<String, Set<String>> edges = <String, Set<String>>{};
    final Map<String, Set<String>> cycleEdges = <String, Set<String>>{};
    for (final LanguagePlugin plugin in plugins.plugins) {
      final DependencyGraph graph = indexed.require(plugin.id).graph;
      for (final String node in graph.nodes) {
        edges[node] = <String>{...graph.dependenciesOf(node)};
        cycleEdges[node] = <String>{...graph.cycleDependenciesOf(node)};
      }
    }
    return DependencyGraph(edges, cycleEdges: cycleEdges);
  }
}

/// Resolves configuration, discovers files, detects languages, and loads text.
final class AnalysisPreparationStage {
  AnalysisPreparationStage({LanguageRegistry? languages})
    : _languages = languages ?? LanguageRegistry.dartFirst();

  final LanguageRegistry _languages;

  PreparedAnalysis prepare(CodeBusterCliOptions options) {
    final String root = Directory(options.root).absolute.path;
    final AnalysisConfig loaded = CodeBusterConfigLoader.loadFromRoot(root);
    final RepositoryDefaults defaults = RepositoryDefaults.infer(
      root,
      includeTests: options.includeAll || options.includeTests,
      includeExamples: options.includeAll || options.includeExamples,
      includeVendored: options.includeAll || options.includeVendored,
    );
    var config = loaded.copyWith(
      ignorePatterns: <String>[
        ...loaded.ignorePatterns,
        if (!options.includeAll) ...defaults.ignores,
        if (!options.includeAll && !options.includeTests)
          ...loaded.classificationTest,
        ...loaded.classificationGenerated,
      ],
      root: root,
      language: options.language.isEmpty ? null : options.language,
      languages: options.languages.isEmpty ? null : options.languages,
      frameworks: defaults.frameworks,
      includes: options.includes.isEmpty ? null : options.includes,
      excludes: options.excludes.isEmpty ? null : options.excludes,
      changedBase: options.changedBase.isEmpty ? null : options.changedBase,
      changedLines: options.changedLines ? true : null,
    );
    final SourceDiscovery discovery = SourceDiscovery(
      config: config,
      languages: _languages,
    );
    final List<SourceFile> files = discovery.discover();
    if (_autoRequested(config)) {
      final List<String> detected = _detectedLanguages(root, files);
      if (detected.isNotEmpty) {
        config = config.copyWith(language: detected.first, languages: detected);
      }
    }
    final Map<String, int> coverage = <String, int>{...discovery.coverage};
    final List<ProcessingDiagnostic> diagnostics = <ProcessingDiagnostic>[];
    final Map<String, String> sources = <String, String>{};
    for (final SourceFile file in files) {
      final List<int> bytes = File(file.absolutePath).readAsBytesSync();
      final bool utf16LittleEndian =
          bytes.length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe;
      final bool utf16BigEndian =
          bytes.length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff;
      if (utf16LittleEndian || utf16BigEndian) {
        sources[file.relativePath] = _decodeUtf16Bom(
          bytes,
          littleEndian: utf16LittleEndian,
        );
        continue;
      }
      try {
        sources[file.relativePath] = utf8.decode(bytes);
      } on FormatException {
        sources[file.relativePath] = utf8.decode(bytes, allowMalformed: true);
        coverage.update(
          'malformed_encoding',
          (int count) => count + 1,
          ifAbsent: () => 1,
        );
        diagnostics.add(
          ProcessingDiagnostic(
            code: 'malformed-utf8',
            severity: ProcessingDiagnosticSeverity.warning,
            stage: 'source-decoding',
            path: file.relativePath,
            message:
                'Invalid UTF-8 bytes were replaced during source decoding.',
          ),
        );
      }
    }
    final Set<String> changedPaths = discovery.changedFiles();
    final Map<String, String> baseSources = discovery.baseSources(sources.keys);
    final Map<String, String> auxiliaryFiles = <String, String>{};
    for (final String relative in const <String>[
      'pubspec.yaml',
      'analysis_options.yaml',
      'l10n.yaml',
      'pyproject.toml',
      'requirements.txt',
    ]) {
      final File file = File('$root${Platform.pathSeparator}$relative');
      if (file.existsSync()) {
        auxiliaryFiles[relative] = file.readAsStringSync();
      }
    }
    for (final String source in sources.values) {
      for (final RegExpMatch match in cachedRegExp(
        r'''['"](assets/[^'"]+)['"]''',
      ).allMatches(source)) {
        final String asset = match.requiredGroup(1);
        auxiliaryFiles['@exists/$asset'] =
            File(
              '$root${Platform.pathSeparator}${asset.replaceAll('/', Platform.pathSeparator)}',
            ).existsSync()
            ? 'true'
            : 'false';
      }
    }
    return PreparedAnalysis(
      root: root,
      config: config,
      files: List<SourceFile>.unmodifiable(files),
      sources: Map<String, String>.unmodifiable(sources),
      changedPaths: changedPaths,
      baseSources: baseSources,
      auxiliaryFiles: Map<String, String>.unmodifiable(auxiliaryFiles),
      coverage: coverage,
      diagnostics: List<ProcessingDiagnostic>.unmodifiable(diagnostics),
      languageVersions: const LanguageVersionDetector().detect(root),
      generatedProvenance: discovery.generatedProvenance,
      changedLineRanges: Map<String, List<ChangedLineRange>>.unmodifiable(
        <String, List<ChangedLineRange>>{
          for (final MapEntry<String, List<ChangedLineRange>> entry
              in discovery.changedLineRanges().entries)
            entry.key: List<ChangedLineRange>.unmodifiable(entry.value),
        },
      ),
    );
  }

  String _decodeUtf16Bom(List<int> bytes, {required bool littleEndian}) {
    final List<int> codeUnits = <int>[];
    for (var index = 2; index + 1 < bytes.length; index += 2) {
      codeUnits.add(
        littleEndian
            ? bytes[index] | (bytes[index + 1] << 8)
            : (bytes[index] << 8) | bytes[index + 1],
      );
    }
    return String.fromCharCodes(codeUnits);
  }

  bool _autoRequested(AnalysisConfig config) =>
      (config.languages.isEmpty && config.language == 'auto') ||
      config.languages.any(
        (String language) => language.toLowerCase() == 'auto',
      );

  List<String> _detectedLanguages(String root, List<SourceFile> files) {
    final Map<String, int> counts = <String, int>{};
    for (final SourceFile file in files) {
      counts.update(file.language, (int count) => count + 1, ifAbsent: () => 1);
    }
    final Set<String> manifests = <String>{};
    if (File('$root${Platform.pathSeparator}pubspec.yaml').existsSync()) {
      manifests.add('dart');
    }
    if (<String>['package.json', 'deno.json', 'deno.jsonc'].any(
      (String name) => File('$root${Platform.pathSeparator}$name').existsSync(),
    )) {
      manifests.add('javascript');
    }
    final List<File> rootFiles = Directory(
      root,
    ).listSync().whereType<File>().toList();
    if (rootFiles.any(
      (File file) => file.path.toLowerCase().endsWith('.csproj'),
    )) {
      manifests.add('csharp');
    }
    if (rootFiles.any(
      (File file) => file.path.toLowerCase().endsWith('.nimble'),
    )) {
      manifests.add('nim');
    }
    final bool oneLanguageOnly = counts.length == 1;
    return _languages.definitions
        .where(
          (LanguageDefinition definition) =>
              (counts[definition.id] ?? 0) >= 2 ||
              manifests.contains(definition.id) ||
              (oneLanguageOnly && (counts[definition.id] ?? 0) > 0),
        )
        .map((LanguageDefinition definition) => definition.id)
        .toList(growable: false);
  }
}
