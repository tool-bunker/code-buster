// Analysis is expensive, so this cache reuses results only when source, configuration, rule versions, and cache format still match.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../catalog/rule_catalog.dart';
import '../core/models.dart';
import '../core/schema_versions.dart';
import '../graph/graph.dart';

final class PersistentAnalysisCache {
  const PersistentAnalysisCache({this.version = 'code-buster-cache-v3'});

  final String version;

  String key({
    required AnalysisConfig config,
    required Map<String, String> sources,
    required String kind,
    Iterable<RuleMetadata>? rules,
  }) {
    final StringBuffer material = StringBuffer()
      ..writeln(version)
      ..writeln(RuleCatalog.versionSignatureFor(rules ?? RuleCatalog.all))
      ..writeln(kind)
      ..writeln(config.language)
      ..writeln(config.languages.join(','))
      ..writeln(config.includes)
      ..writeln(config.excludes)
      ..writeln(config.changedBase)
      ..writeln(config.changedLines)
      ..writeln(config.entryPoints)
      ..writeln(config.ignorePatterns)
      ..writeln(config.classificationProduction)
      ..writeln(config.classificationTest)
      ..writeln(config.classificationGenerated)
      ..writeln(config.minDuplicationLines)
      ..writeln(config.duplicationMode.name)
      ..writeln(config.complexityThreshold)
      ..writeln(config.cognitiveThreshold)
      ..writeln(config.maxFileLines)
      ..writeln(config.maxFunctionLines)
      ..writeln(config.csharpDeadCode)
      ..writeln(config.qualityProfile)
      ..writeln(config.qualityGates)
      ..writeln(config.ruleGroups.toList()..sort())
      ..writeln(
        config.groupModes.entries
            .map(
              (MapEntry<String, RuleMode> entry) =>
                  '${entry.key}=${entry.value.name}',
            )
            .toList()
          ..sort(),
      )
      ..writeln(
        config.ruleModes.entries
            .map(
              (MapEntry<String, RuleMode> entry) =>
                  '${entry.key}=${entry.value.name}',
            )
            .toList()
          ..sort(),
      )
      ..writeln(config.severityOverrides)
      ..writeln(config.disabledRules.toList()..sort())
      ..writeln(<Map<String, Object>>[
        for (final PatternRule rule in config.patternRules)
          <String, Object>{
            'id': rule.id,
            'severity': rule.severity.name,
            'pattern': rule.pattern,
            'patternNot': rule.patternNot,
            'message': rule.message,
            'suggestion': rule.suggestion,
            'fix': rule.fix,
            'category': rule.category,
          },
      ])
      ..writeln(config.structureSourceRoots)
      ..writeln(config.structureMaxTopLevelFiles)
      ..writeln(config.structureAllowedTopLevel)
      ..writeln(config.structureRequiredDirectories)
      ..writeln(config.architectureLayers)
      ..writeln(config.architectureAllowedDependencies)
      ..writeln(config.architectureProfile)
      ..writeln(config.mvvmViews)
      ..writeln(config.mvvmViewModels)
      ..writeln(config.mvvmModels)
      ..writeln(config.mvvmRepositories)
      ..writeln(config.mvvmStrictViewModelBoundary)
      ..writeln(config.architectureDeniedDependencies);
    final File configFile = File(
      '${config.root}${Platform.pathSeparator}code-buster.toml',
    );
    if (configFile.existsSync()) {
      material.writeln(configFile.readAsStringSync());
    }
    final Set<String> styleConfigs = <String>{};
    for (final String path in sources.keys.toList()..sort()) {
      material
        ..writeln(path)
        ..writeln(sha256.convert(utf8.encode(sources[path]!)));
      var directory = File(
        '${config.root}${Platform.pathSeparator}${path.replaceAll('/', Platform.pathSeparator)}',
      ).parent;
      final String rootPath = Directory(config.root).absolute.path;
      while (directory.absolute.path.startsWith(rootPath)) {
        for (final String name in const <String>[
          '.prettierrc',
          '.prettierrc.json',
          '.prettierrc.js',
          'prettier.config.js',
          '.editorconfig',
          'biome.json',
        ]) {
          final File candidate = File(
            '${directory.path}${Platform.pathSeparator}$name',
          );
          if (candidate.existsSync()) styleConfigs.add(candidate.absolute.path);
        }
        if (directory.absolute.path == rootPath) break;
        directory = directory.parent;
      }
    }
    for (final String stylePath in styleConfigs.toList()..sort()) {
      material
        ..writeln(stylePath)
        ..writeln(File(stylePath).readAsStringSync());
    }
    return sha256.convert(utf8.encode(material.toString())).toString();
  }

  /// Reads cached findings, returning null for misses or corrupt entries.
  List<Finding>? loadFindings({
    required AnalysisConfig config,
    required String key,
  }) {
    final File file = _file(config.root, 'findings-$key.json');
    if (!file.existsSync()) return null;
    try {
      final Object? decoded = jsonDecode(file.readAsStringSync());
      if (decoded is! Map<String, Object?> ||
          decoded['schemaVersion'] != cacheSchemaVersion ||
          decoded['kind'] != 'findings' ||
          decoded['entries'] is! List<Object?>) {
        return null;
      }
      return (decoded['entries']! as List<Object?>)
          .whereType<Map<String, Object?>>()
          .map(_findingFromJson)
          .toList(growable: false);
    } on Object {
      return null;
    }
  }

  /// Reads a cached dependency graph, returning null on miss/corruption.
  DependencyGraph? loadGraph({
    required AnalysisConfig config,
    required String key,
  }) {
    final File file = _file(config.root, 'graph-$key.json');
    if (!file.existsSync()) return null;
    try {
      final Object? decoded = jsonDecode(file.readAsStringSync());
      if (decoded is! Map<String, Object?> ||
          decoded['schemaVersion'] != cacheSchemaVersion ||
          decoded['kind'] != 'graph' ||
          decoded['edges'] is! Map<String, Object?>) {
        return null;
      }
      final Map<String, Object?> edges =
          decoded['edges']! as Map<String, Object?>;
      final Map<String, Object?> cycleEdges =
          decoded['cycleEdges'] is Map<String, Object?>
          ? decoded['cycleEdges']! as Map<String, Object?>
          : edges;
      return DependencyGraph(
        <String, Iterable<String>>{
          for (final MapEntry<String, Object?> entry in edges.entries)
            entry.key: (entry.value! as List<Object?>).cast<String>(),
        },
        cycleEdges: <String, Iterable<String>>{
          for (final MapEntry<String, Object?> entry in cycleEdges.entries)
            entry.key: (entry.value! as List<Object?>).cast<String>(),
        },
      );
    } on Object {
      return null;
    }
  }

  /// Atomically stores a dependency graph.
  void storeGraph({
    required AnalysisConfig config,
    required String key,
    required DependencyGraph graph,
  }) {
    try {
      final File file = _file(config.root, 'graph-$key.json');
      file.parent.createSync(recursive: true);
      final File temporary = File('${file.path}.tmp');
      temporary.writeAsStringSync(
        jsonEncode(<String, Object>{
          'schemaVersion': cacheSchemaVersion,
          'kind': 'graph',
          'edges': <String, Object>{
            for (final String node in graph.nodes)
              node: graph.dependenciesOf(node),
          },
          'cycleEdges': <String, Object>{
            for (final String node in graph.nodes)
              node: graph.cycleDependenciesOf(node),
          },
        }),
      );
      temporary.renameSync(file.path);
    } on FileSystemException {
      // Cache writes are opportunistic.
    }
  }

  /// Atomically stores raw findings. Cache failures never fail analysis.
  void storeFindings({
    required AnalysisConfig config,
    required String key,
    required Iterable<Finding> findings,
  }) {
    try {
      final File file = _file(config.root, 'findings-$key.json');
      file.parent.createSync(recursive: true);
      final File temporary = File('${file.path}.tmp');
      temporary.writeAsStringSync(
        jsonEncode(<String, Object>{
          'schemaVersion': cacheSchemaVersion,
          'kind': 'findings',
          'entries': findings.map(_findingJson).toList(),
        }),
      );
      temporary.renameSync(file.path);
    } on FileSystemException {
      // A read-only project or racing process must not prevent analysis.
    }
  }

  File _file(String root, String name) => File(
    '$root${Platform.pathSeparator}.code-buster-cache${Platform.pathSeparator}$name',
  );

  Map<String, Object> _findingJson(Finding finding) => <String, Object>{
    'code': finding.code,
    'severity': finding.severity.name,
    'path': finding.path,
    'line': finding.line,
    'end_line': finding.endLine,
    'message': finding.message,
    'confidence': finding.confidence,
    'why': finding.why,
    'suggestion': finding.suggestion,
    'related_files': finding.relatedFiles,
    'snippet': finding.snippet,
    'code_flow': finding.codeFlow
        .map((CodeFlowStep step) => step.toJson())
        .toList(growable: false),
  };

  Finding _findingFromJson(Map<String, Object?> json) => Finding(
    code: json['code']! as String,
    severity: RuleSeverity.parse(json['severity']! as String),
    path: json['path']! as String,
    line: json['line']! as int,
    endLine: json['end_line']! as int,
    message: json['message']! as String,
    confidence: json['confidence']! as String,
    why: json['why']! as String,
    suggestion: json['suggestion']! as String,
    relatedFiles: (json['related_files']! as List<Object?>).cast<String>(),
    snippet: json['snippet']! as String,
    codeFlow: ((json['code_flow'] as List<Object?>?) ?? const <Object?>[])
        .whereType<Map<String, Object?>>()
        .map(
          (Map<String, Object?> step) => CodeFlowStep(
            path: step['path']! as String,
            line: step['line']! as int,
            message: step['message']! as String,
          ),
        )
        .toList(growable: false),
  );
}
