// Rules from many registries must execute deterministically and fail independently, which is handled at this boundary.

import '../cli/cli_contract.dart';
import '../controls/finding_controls.dart';
import '../core/models.dart';
import '../core/rule.dart';
import '../discovery/discovery.dart';
import '../graph/graph.dart';
import '../plugins/language_plugin.dart';
import '../rules/architecture/architecture.dart';
import '../rules/architecture/mvvm_architecture.dart';
import '../rules/duplication/duplication.dart';
import '../rules/regex/regex_rules.dart';
import '../rules/repository_rules.dart';
import 'analysis.dart';
import 'analysis_pipeline.dart';

/// Executes repository, graph, language, and cross-language rules.
final class RuleExecutionStage {
  /// Creates a stage with validated built-in registries.
  RuleExecutionStage({
    LanguagePluginRegistry? languagePlugins,
    RuleRegistry? repositoryRules,
  }) : _languagePlugins = languagePlugins ?? LanguagePluginRegistry.standard(),
       _repositoryRules = repositoryRules ?? _standardRepositoryRules;

  final LanguagePluginRegistry _languagePlugins;
  final RuleRegistry _repositoryRules;

  static final RuleRegistry _standardRepositoryRules = repositoryRuleRegistry;
  static final RegExp _runtimeDiscoveredTestDirectory = RegExp(
    r'(^|/)(?:__tests__|test|tests|spec|specs)(?:/|$)',
  );

  static bool _isRuntimeDiscoveredTestSource(String path) =>
      _runtimeDiscoveredTestDirectory.hasMatch(path.replaceAll(r'\', '/'));

  static final RegExp _auxiliaryDirectory = RegExp(
    r'(^|/)(?:example|examples|fixture|fixtures|bench|benchmark|benchmarks)(?:/|$)',
  );

  static bool _isDeadFileCandidate(String path) {
    final String normalized = path.replaceAll(r'\', '/');
    return !_isRuntimeDiscoveredTestSource(normalized) &&
        !_auxiliaryDirectory.hasMatch(normalized);
  }

  static bool _isDartRoot(String path, String source) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    return (segments.length == 2 && segments.first == 'bin') ||
        (segments.length == 2 && segments.first == 'lib') ||
        RegExp(
          r'\b(?:FutureOr<\s*void\s*>|Future<\s*void\s*>|void)\s+main\s*\(',
        ).hasMatch(source);
  }

  static bool _isPythonRoot(String path) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    return segments.last == '__main__.py' ||
        (segments.length == 1 && segments.single == 'main.py');
  }

  static bool _isMainSource(String path) {
    final String name = path.replaceAll(r'\', '/').split('/').last;
    final int extension = name.lastIndexOf('.');
    return (extension < 0 ? name : name.substring(0, extension)) == 'main';
  }

  static bool _isPublicLuaModuleRoot(String path) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    if (segments.length == 3 && segments.first == 'lua') {
      return segments.last.endsWith('.lua') || segments.last.endsWith('.luau');
    }
    return segments.length == 4 &&
        segments.first == 'lua' &&
        segments[2] == 'plugins' &&
        (segments.last.endsWith('.lua') || segments.last.endsWith('.luau'));
  }

  static bool _isConventionalLuaRepositoryRoot(String path) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    final String name = segments.last;
    final bool isInit = name == 'init.lua' || name == 'init.luau';
    return isInit &&
        (segments.length == 1 ||
            (segments.length == 2 && segments.first == 'src'));
  }

  static bool _isNeovimRuntimeRoot(String path) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    return segments.length == 2 &&
        const <String>{'plugin', 'ftplugin'}.contains(segments.first) &&
        segments.last.endsWith('.lua');
  }

  /// Built-in repository rules in deterministic execution order.
  static Iterable<CodeBusterRule> get standardRepositoryRules =>
      _standardRepositoryRules.rules;

  /// Executes rules selected by [command] over [prepared].
  List<Finding> execute(
    CodeBusterCommand command,
    IndexedAnalysis indexed,
    GraphAnalysis graph,
  ) {
    final PreparedAnalysis prepared = indexed.prepared;
    final AnalysisConfig config = prepared.config;
    final Map<String, String> sources = prepared.sources;
    final List<SourceFile> files = prepared.files;
    final List<String> luaDeadFileCandidates = sources.keys
        .where(
          (String path) =>
              !_isRuntimeDiscoveredTestSource(path) &&
              (path.endsWith('.lua') || path.endsWith('.luau')),
        )
        .toList(growable: false);
    final Set<String> defaultGraphRoots = graph.defaultRoots(
      config.entryPoints,
    );
    final bool hasConfiguredGraphRoot = config.entryPoints.any(
      graph.graph.nodes.contains,
    );
    final bool hasInferredLuaMain = defaultGraphRoots.any(
      (String root) =>
          luaDeadFileCandidates.contains(root) && _isMainSource(root),
    );
    final Set<String> publicLuaModuleRoots = sources.keys
        .where(_isPublicLuaModuleRoot)
        .where(graph.graph.nodes.contains)
        .toSet();
    final Set<String> conventionalLuaRepositoryRoots = sources.keys
        .where(_isConventionalLuaRepositoryRoot)
        .where(graph.graph.nodes.contains)
        .toSet();
    final Set<String> neovimRuntimeRoots = sources.keys
        .where(_isNeovimRuntimeRoot)
        .where(graph.graph.nodes.contains)
        .toSet();
    final Set<String> luaShebangRoots = files
        .where(
          (SourceFile file) =>
              file.language == 'lua' &&
              !file.relativePath.split('/').last.contains('.'),
        )
        .map((SourceFile file) => file.relativePath)
        .where(graph.graph.nodes.contains)
        .toSet();
    final bool hasConventionalLuaRoot =
        publicLuaModuleRoots.isNotEmpty ||
        conventionalLuaRepositoryRoots.isNotEmpty ||
        neovimRuntimeRoots.isNotEmpty ||
        luaShebangRoots.isNotEmpty;
    final Set<String> configuredGraphRoots = config.entryPoints
        .where(graph.graph.nodes.contains)
        .toSet();
    final List<String> dartDeadFileCandidates = sources.keys
        .where(
          (String path) => path.endsWith('.dart') && _isDeadFileCandidate(path),
        )
        .toList(growable: false);
    final Set<String> dartGraphRoots = <String>{
      ...configuredGraphRoots.where((String path) => path.endsWith('.dart')),
      ...dartDeadFileCandidates.where(
        (String path) => _isDartRoot(path, sources[path]!),
      ),
    };
    final List<String> pythonDeadFileCandidates = sources.keys
        .where(
          (String path) => path.endsWith('.py') && _isDeadFileCandidate(path),
        )
        .toList(growable: false);
    final Set<String> pythonGraphRoots = <String>{
      ...configuredGraphRoots.where((String path) => path.endsWith('.py')),
      ...pythonDeadFileCandidates.where(_isPythonRoot),
    };
    final Set<String> graphRoots = <String>{
      if (hasConfiguredGraphRoot ||
          hasInferredLuaMain ||
          !hasConventionalLuaRoot)
        ...defaultGraphRoots,
      ...publicLuaModuleRoots,
      ...conventionalLuaRepositoryRoots,
      ...neovimRuntimeRoots,
      ...luaShebangRoots,
    };
    final Iterable<String> luaDeadFileEligible =
        hasConfiguredGraphRoot || hasInferredLuaMain || hasConventionalLuaRoot
        ? luaDeadFileCandidates
        : const <String>[];
    final List<Finding> graphFindings = <Finding>[
      ...graph.cycleFindings().where((Finding finding) {
        final Iterable<String> component = <String>[
          finding.path,
          ...finding.relatedFiles,
        ];
        // Nominal Java/C# files and Dart files routinely reference one another
        // within their owning package. Package plugins report the stable
        // architecture boundary instead.
        final bool nominalCycle = component.every(
          (String sourcePath) =>
              sourcePath.endsWith('.java') || sourcePath.endsWith('.cs'),
        );
        final bool dartFileCycle = component.every(
          (String sourcePath) => sourcePath.endsWith('.dart'),
        );
        return !nominalCycle && !dartFileCycle;
      }),
      ...ArchitectureAnalysis(graph.graph, config).findings(),
      ...MvvmArchitectureAnalysis(graph.graph, config).findings(),
      ...graph.deadFileFindings(
        roots: graphRoots,
        eligibleNodes: luaDeadFileEligible,
      ),
      ...graph.deadFileFindings(
        roots: dartGraphRoots,
        eligibleNodes: dartGraphRoots.isEmpty
            ? const <String>[]
            : dartDeadFileCandidates,
      ),
      ...graph.deadFileFindings(
        roots: pythonGraphRoots,
        eligibleNodes: pythonGraphRoots.isEmpty
            ? const <String>[]
            : pythonDeadFileCandidates,
      ),
      ...graph.deadFileFindings(
        roots: graphRoots,
        eligibleNodes: sources.keys.where(
          (String path) =>
              !_isRuntimeDiscoveredTestSource(path) &&
              path.endsWith('.cs') &&
              config.csharpDeadCode,
        ),
      ),
    ];
    final DuplicationAnalysis duplication = DuplicationAnalysis();
    final RepositoryAnalysis repository = RepositoryAnalysis();
    final List<FunctionSource> functions = <FunctionSource>[
      ...indexed.require('cpp').functions,
      ...indexed.require('csharp').functions,
      ...indexed.require('dart').functions,
      ...indexed.require('go').functions,
      ...indexed.require('java').functions,
      ...indexed.require('javascript').functions,
      ...indexed.require('nim').functions,
      ...indexed.require('wren').functions,
      ...indexed.require('python').functions,
    ];
    final Map<String, List<String>> sourceLines =
        Map<String, List<String>>.unmodifiable(
          sources.map(
            (String path, String source) =>
                MapEntry<String, List<String>>(path, source.split('\n')),
          ),
        );
    final List<Finding> styleFindings =
        <Finding>[
          ...indexed.require('html').findings,
          ...indexed.require('css').findings,
          ...indexed.require('wren').findings,
          ...indexed.require('nim').findings,
          ...indexed.require('lua').findings,
          ...indexed.require('javascript').findings,
          ...indexed.require('python').findings,
          ...indexed.require('sql').findings,
          ...indexed.require('cpp').findings,
          ...indexed.require('csharp').findings,
          ...indexed.require('java').findings,
          ...indexed.require('dart').findings,
          ..._repositoryRules.rules.expand(
            (CodeBusterRule rule) => rule.analyze(
              RuleContext(
                config: config,
                sources: sources,
                sourceLines: sourceLines,
                language: 'repository',
                graph: graph.graph,
              ),
            ),
          ),
          ...RegexRuleAnalysis().findings(sources),
          ...PatternRuleAnalysis().findings(sources, config.patternRules),
        ]..sort((Finding left, Finding right) {
          if (left.code.startsWith('nim-') && right.code.startsWith('nim-')) {
            return _languagePlugins.compareFindings('nim', left, right);
          }
          final int path = left.path.compareTo(right.path);
          if (path != 0) return path;
          final int line = left.line.compareTo(right.line);
          if (line != 0) return line;
          const Set<String> genericLayout = <String>{
            'tab-indent',
            'trailing-whitespace',
            'long-line',
          };
          return (genericLayout.contains(left.code) ? 0 : 1).compareTo(
            genericLayout.contains(right.code) ? 0 : 1,
          );
        });
    final List<Finding> all = <Finding>[
      ...repository.complexityFindings(functions: functions, config: config),
      ...repository.fileFindings(sources: sources, config: config),
      ...graphFindings,
      ...duplication.exactBlocks(sources, minLines: config.minDuplicationLines),
      if (config.duplicationMode != DuplicationMode.exact)
        ...duplication.nearDuplicateFunctions(functions),
      if (config.duplicationMode == DuplicationMode.semantic)
        ...duplication.parallelContractImplementations(functions),
      ...duplication.repeatedConditions(sources),
      ...FeatureFlagAnalysis().findings(sources),
      ...repository.structureFindings(files: files, config: config),
      ...styleFindings,
    ];
    return switch (command) {
      CodeBusterCommand.summary ||
      CodeBusterCommand.review ||
      CodeBusterCommand.pr ||
      CodeBusterCommand.test => all,
      CodeBusterCommand.graph => const <Finding>[],
      CodeBusterCommand.dead => <Finding>[
        ...graphFindings,
        ...all.where(
          (Finding finding) =>
              finding.code == 'dead-export' || finding.code == 're-export',
        ),
      ],
      CodeBusterCommand.duplication || CodeBusterCommand.clusters =>
        all
            .where(
              (Finding finding) =>
                  finding.code == 'duplicate-block' ||
                  finding.code == 'near-duplicate-function' ||
                  finding.code == 'parallel-contract-implementation' ||
                  finding.code == 'dart-overlapping-data-model' ||
                  finding.code == 'repeated-condition',
            )
            .toList(growable: false),
      CodeBusterCommand.structure =>
        all
            .where((Finding finding) => finding.code.startsWith('structure-'))
            .toList(growable: false),
      CodeBusterCommand.flags =>
        all
            .where((Finding finding) => finding.code == 'feature-flag')
            .toList(growable: false),
      CodeBusterCommand.complexity =>
        all
            .where(
              (Finding finding) =>
                  finding.code == 'complex-function' ||
                  finding.code == 'long-function' ||
                  finding.code == 'goto-statement',
            )
            .toList(growable: false),
      _ => const <Finding>[],
    };
  }
}
