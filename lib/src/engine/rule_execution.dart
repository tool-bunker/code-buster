// Rules from many registries must execute deterministically and fail independently, which is handled at this boundary.

import 'dart:io';

import 'package:path/path.dart' as path;

import '../catalog/rule_catalog.dart';
import '../cli/cli_contract.dart';
import '../controls/finding_controls.dart';
import '../core/models.dart';
import '../core/regexp_cache.dart';
import '../core/rule.dart';
import '../core/rule_policy.dart';
import '../discovery/discovery.dart';
import '../graph/graph.dart';
import '../languages/dart/dart_adapter.dart';
import '../plugins/language_plugin.dart';
import '../rules/architecture/architecture.dart';
import '../rules/architecture/mvvm_architecture.dart';
import '../rules/duplication/duplication.dart';
import '../rules/framework_rules.dart';
import '../rules/regex/regex_rules.dart';
import '../rules/repository_rules.dart';
import 'analysis.dart';
import 'analysis_execution_plan.dart';
import 'analysis_pipeline.dart';

typedef FindingFamilyCache =
    List<Finding> Function(
      String family,
      Map<String, String>? sourceInputs,
      List<Finding> Function() analyze,
    );

/// Executes repository, graph, language, and cross-language rules.
final class RuleExecutionStage {
  RuleExecutionStage({
    LanguagePluginRegistry? languagePlugins,
    RuleRegistry? repositoryRules,
    FindingFamilyCache? cacheFamily,
  }) : _languagePlugins = languagePlugins ?? LanguagePluginRegistry.standard(),
       _repositoryRules = repositoryRules ?? _standardRepositoryRules,
       _cacheFamily = cacheFamily;

  final LanguagePluginRegistry _languagePlugins;
  final RuleRegistry _repositoryRules;
  final FindingFamilyCache? _cacheFamily;

  /// Milliseconds spent in each rule family during the latest execution.
  Map<String, int> get familyTimings =>
      Map<String, int>.unmodifiable(_familyTimings);
  final Map<String, int> _familyTimings = <String, int>{};

  static final RuleRegistry _standardRepositoryRules = repositoryRuleRegistry;
  static final RegExp _runtimeDiscoveredTestDirectory = cachedRegExp(
    r'(^|/)(?:__tests__|test|tests|spec|specs)(?:/|$)',
  );

  static bool _isRuntimeDiscoveredTestSource(String path) =>
      _runtimeDiscoveredTestDirectory.hasMatch(path.replaceAll(r'\', '/'));

  static final RegExp _auxiliaryDirectory = cachedRegExp(
    r'(^|/)(?:example|examples|fixture|fixtures|bench|benchmark|benchmarks)(?:/|$)',
  );

  static bool _isDeadFileCandidate(String path) {
    final String normalized = path.replaceAll(r'\', '/');
    return !_isRuntimeDiscoveredTestSource(normalized) &&
        !_auxiliaryDirectory.hasMatch(normalized);
  }

  static bool _isDartRoot(
    String path,
    String source,
    DartWorkspaceLayout workspace,
  ) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    return workspace.isPublicRoot(path) ||
        (segments.length == 2 &&
            (segments.first == 'lib' || segments.first == 'bin')) ||
        cachedRegExp(
          r'\b(?:FutureOr<\s*void\s*>|Future<\s*void\s*>|void)\s+main\s*\(',
        ).hasMatch(source);
  }

  static Set<String> _dartBuilderRoots(
    String root,
    Iterable<String> sourcePaths,
  ) {
    final Set<String> sources = sourcePaths.toSet();
    final Set<String> packageRoots = <String>{};
    for (final String sourcePath in sources) {
      final List<String> segments = sourcePath.replaceAll(r'\', '/').split('/');
      final int libIndex = segments.indexOf('lib');
      if (libIndex >= 0) {
        packageRoots.add(segments.take(libIndex).join('/'));
      }
    }

    final Set<String> roots = <String>{};
    for (final String packageRoot in packageRoots) {
      final File buildConfig = File(
        path.joinAll(<String>[root, ...packageRoot.split('/'), 'build.yaml']),
      );
      if (!buildConfig.existsSync()) continue;
      final RegExp imports = cachedRegExp(
        r'''^\s*import:\s*["']package:([^/]+)/([^"']+)["']\s*$''',
        multiLine: true,
      );
      for (final RegExpMatch match in imports.allMatches(
        buildConfig.readAsStringSync(),
      )) {
        final String candidate = path.posix.join(
          packageRoot,
          'lib',
          match.group(2)!,
        );
        if (sources.contains(candidate)) roots.add(candidate);
      }
    }
    return roots;
  }

  static Set<String> _dartGeneratedDependencyRoots(
    PreparedAnalysis prepared,
    DartWorkspaceLayout workspace,
  ) {
    final Map<String, String> generatedSources = <String, String>{};
    for (final GeneratedSourceProvenance provenance
        in prepared.generatedProvenance) {
      if (!provenance.path.endsWith('.dart')) continue;
      final File generated = File(
        path.joinAll(<String>[
          prepared.root,
          ...provenance.path.replaceAll(r'\', '/').split('/'),
        ]),
      );
      if (generated.existsSync()) {
        generatedSources[provenance.path] = generated.readAsStringSync();
      }
    }
    if (generatedSources.isEmpty) return const <String>{};

    final Map<String, String> graphSources = <String, String>{
      ...prepared.sources,
      ...generatedSources,
    };
    final DependencyGraph generatedGraph = DartGraphAdapter(
      root: prepared.root,
      packageName: '',
      packageLibDirectories: workspace.packageLibDirectories,
    ).build(graphSources);
    final Set<String> generatedReachable = GraphAnalysis(
      generatedGraph,
    ).reachableFrom(generatedSources.keys);
    return generatedReachable.where(prepared.sources.containsKey).toSet();
  }

  static String? _pythonPublicPackagePrefix(String path) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    if (segments.last != '__init__.py') {
      return null;
    }
    if (segments.length == 2) {
      return '${segments.first}/';
    }
    final int src = segments.lastIndexOf('src');
    if (src >= 0 && src == segments.length - 3) {
      return '${segments.take(src + 2).join('/')}/';
    }
    return null;
  }

  static bool _isPythonExecutableRoot(String path, String source) {
    final List<String> segments = path.replaceAll(r'\', '/').split('/');
    return segments.last == '__main__.py' ||
        segments.last == 'main.py' ||
        cachedRegExp(
          r'''^\s*if\s+__name__\s*==\s*["']__main__["']\s*:''',
          multiLine: true,
        ).hasMatch(source);
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
  // code-buster-ignore complex-function: command dispatch keeps shared graph preparation and mutually exclusive result views in one ordered pipeline.
  List<Finding> execute(
    CodeBusterCommand command,
    IndexedAnalysis indexed,
    GraphAnalysis graph, {
    String only = '',
    String group = '',
  }) {
    final PreparedAnalysis prepared = indexed.prepared;
    final AnalysisConfig config = prepared.config;
    final Map<String, String> sources = prepared.sources;
    final List<SourceFile> files = prepared.files;
    _familyTimings.clear();
    final AnalysisExecutionPlan plan = AnalysisExecutionPlan(
      command: command,
      config: config,
      only: only,
      group: group,
    );
    if (command == CodeBusterCommand.graph) return const <Finding>[];
    if (command == CodeBusterCommand.structure ||
        (plan.only.isNotEmpty && plan.only.startsWith('structure-'))) {
      return _findingFamily(
        'structure',
        () => RepositoryAnalysis()
            .structureFindings(files: files, config: config)
            .where((Finding finding) => plan.allows(finding.code))
            .toList(growable: false),
        sourceInputs: <String, String>{
          for (final String path in sources.keys) path: '',
        },
      );
    }
    if (command == CodeBusterCommand.flags || plan.only == 'feature-flag') {
      return _perSourceFamily(
        'featureFlags',
        sources,
        (Map<String, String> selected) => FeatureFlagAnalysis()
            .findings(selected)
            .where((Finding finding) => plan.allows(finding.code))
            .toList(growable: false),
      );
    }
    if (command == CodeBusterCommand.complexity ||
        AnalysisExecutionPlan.complexityRuleIds.contains(plan.only)) {
      return _focusedComplexity(indexed, plan);
    }
    if (command == CodeBusterCommand.duplication ||
        command == CodeBusterCommand.clusters ||
        AnalysisExecutionPlan.duplicationRuleIds.contains(plan.only)) {
      return _focusedDuplication(indexed, plan);
    }
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
    final DartWorkspaceLayout dartWorkspace = DartWorkspaceLayout.discover(
      config.root,
      dartDeadFileCandidates,
    );
    final Set<String> dartGraphRoots = <String>{
      ...configuredGraphRoots.where((String path) => path.endsWith('.dart')),
      ...dartDeadFileCandidates.where(
        (String path) => _isDartRoot(path, sources[path]!, dartWorkspace),
      ),
      ..._dartBuilderRoots(config.root, dartDeadFileCandidates),
      ..._dartGeneratedDependencyRoots(prepared, dartWorkspace),
    };
    final List<String> pythonDeadFileCandidates = sources.keys
        .where(
          (String path) => path.endsWith('.py') && _isDeadFileCandidate(path),
        )
        .toList(growable: false);
    final Set<String> configuredPythonRoots = configuredGraphRoots
        .where((String path) => path.endsWith('.py'))
        .toSet();
    final Set<String> pythonPublicPackagePrefixes = pythonDeadFileCandidates
        .map(_pythonPublicPackagePrefix)
        .nonNulls
        .toSet();
    final Set<String> pythonExecutableRoots = pythonDeadFileCandidates.where((
      String path,
    ) {
      final String? source = sources[path];
      return source != null && _isPythonExecutableRoot(path, source);
    }).toSet();
    final Set<String> pythonAppPrefixes = pythonExecutableRoots
        .where(
          (String path) =>
              path == 'main.py' ||
              path.endsWith('/main.py') ||
              path.endsWith('/__main__.py'),
        )
        .map((String path) {
          final int separator = path.lastIndexOf('/');
          return separator < 0 ? '' : path.substring(0, separator + 1);
        })
        .toSet();
    final Set<String> pythonNamespacePackagePrefixes =
        configuredPythonRoots.isEmpty
        ? (pythonDeadFileCandidates
              .where((String path) => path.contains('/'))
              .map((String path) => '${path.split('/').first}/')
              .toSet()
            ..removeAll(pythonAppPrefixes))
        : const <String>{};
    final Set<String> pythonGraphRoots = <String>{
      ...configuredPythonRoots,
      ...pythonExecutableRoots,
      ...pythonDeadFileCandidates.where(
        (String path) => pythonPublicPackagePrefixes.any(path.startsWith),
      ),
      ...pythonDeadFileCandidates.where(
        (String path) => pythonNamespacePackagePrefixes.any(path.startsWith),
      ),
    };
    final Iterable<String> pythonDeadFileEligible =
        configuredPythonRoots.isNotEmpty
        ? pythonDeadFileCandidates
        : pythonDeadFileCandidates.where(
            (String path) =>
                pythonPublicPackagePrefixes.any(path.startsWith) ||
                pythonNamespacePackagePrefixes.any(path.startsWith) ||
                pythonAppPrefixes.any(path.startsWith),
          );
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
        // Nominal Java/C# files and Dart/Rust modules routinely reference one
        // another within their owning package. Package plugins report the
        // stable architecture boundary instead.
        final bool nominalCycle = component.every(
          (String sourcePath) =>
              sourcePath.endsWith('.java') || sourcePath.endsWith('.cs'),
        );
        final bool moduleFileCycle = component.every(
          (String sourcePath) =>
              sourcePath.endsWith('.dart') || sourcePath.endsWith('.rs'),
        );
        return !nominalCycle && !moduleFileCycle;
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
        eligibleNodes: pythonDeadFileEligible,
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
      ...indexed.require('mojo').functions,
      ...indexed.require('wren').functions,
      ...indexed.require('python').functions,
      ...indexed.require('rust').functions,
    ];
    final Map<String, List<String>> sourceLines =
        Map<String, List<String>>.unmodifiable(
          sources.map(
            (String path, String source) =>
                MapEntry<String, List<String>>(path, source.split('\n')),
          ),
        );
    final RuleContext repositoryContext = RuleContext(
      config: config,
      sources: sources,
      sourceLines: sourceLines,
      language: 'repository',
      graph: graph.graph,
      changedPaths: prepared.changedPaths,
      baseSources: prepared.baseSources,
      auxiliaryFiles: prepared.auxiliaryFiles,
    );
    final List<Finding> repositoryRuleFindings = _findingFamily(
      'repositoryRules',
      () {
        final List<Finding> findings = <Finding>[];
        for (final CodeBusterRule rule in <CodeBusterRule>[
          ..._repositoryRules.rules,
          ...frameworkRepositoryRules(config.frameworks),
        ]) {
          if (!plan.allows(rule.metadata.id) ||
              !ruleFrameworksAreActive(rule.metadata, config)) {
            continue;
          }
          final Stopwatch stopwatch = Stopwatch()..start();
          findings.addAll(rule.analyze(repositoryContext));
          _familyTimings['repositoryRules.${rule.metadata.id}'] =
              stopwatch.elapsedMilliseconds;
        }
        return findings;
      },
    );
    final List<Finding> styleFindings =
        <Finding>[
          ..._allLanguageFindings(indexed),
          ...repositoryRuleFindings,
          ..._perSourceFamily(
            'regexRules',
            sources,
            (Map<String, String> selected) =>
                RegexRuleAnalysis().findings(selected),
          ),
          ..._perSourceFamily(
            'patternRules',
            sources,
            (Map<String, String> selected) =>
                PatternRuleAnalysis().findings(selected, config.patternRules),
          ),
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
    final List<Finding> base = <Finding>[
      if (plan.requires(AnalysisExecutionPlan.complexityRuleIds))
        ..._findingFamily(
          'complexity',
          () => repository.complexityFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('single-use-trivial-wrapper'))
        ..._findingFamily(
          'yagni.trivialWrapper',
          () => repository.trivialWrapperFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('single-product-factory'))
        ..._findingFamily(
          'yagni.singleProductFactory',
          () => repository.singleProductFactoryFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('constant-argument-parameter'))
        ..._findingFamily(
          'yagni.constantArgument',
          () => repository.constantArgumentFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('unused-customization-hook'))
        ..._findingFamily(
          'yagni.unusedCustomizationHook',
          () => repository.unusedCustomizationHookFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('unused-optional-parameter'))
        ..._findingFamily(
          'yagni.unusedOptionalParameter',
          () => repository.unusedOptionalParameterFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('unused-configuration-option'))
        ..._findingFamily(
          'yagni.unusedConfigurationOption',
          () => repository.unusedConfigurationOptionFindings(
            functions: functions,
            config: config,
          ),
        ),
      if (plan.allows('large-file') || plan.allows('goto-statement'))
        ..._perSourceFamily(
          'file',
          sources,
          (Map<String, String> selected) =>
              repository.fileFindings(sources: selected, config: config),
        ),
      ...graphFindings.where((Finding finding) => plan.allows(finding.code)),
      if (plan.allows('duplicate-block'))
        ..._findingFamily(
          'duplication.exact',
          () => duplication.exactBlocks(
            sources,
            minLines: config.minDuplicationLines,
          ),
        ),
      if (plan.allows('near-duplicate-function') &&
          config.duplicationMode != DuplicationMode.exact)
        ..._findingFamily(
          'duplication.near',
          () => duplication.nearDuplicateFunctions(functions),
        ),
      if (plan.allows('parallel-contract-implementation') &&
          config.duplicationMode == DuplicationMode.semantic)
        ..._findingFamily(
          'duplication.semantic',
          () => duplication.parallelContractImplementations(functions),
        ),
      if (plan.allows('repeated-condition'))
        ..._findingFamily(
          'duplication.conditions',
          () => duplication.repeatedConditions(sources),
        ),
      if (plan.allows('feature-flag'))
        ..._perSourceFamily(
          'featureFlags',
          sources,
          (Map<String, String> selected) =>
              FeatureFlagAnalysis().findings(selected),
        ),
      if (plan.requiresMetadata(
        RuleCatalog.all.where(
          (RuleMetadata metadata) => metadata.id.startsWith('structure-'),
        ),
      ))
        ..._findingFamily(
          'structure',
          () => repository.structureFindings(files: files, config: config),
          sourceInputs: <String, String>{
            for (final String path in sources.keys) path: '',
          },
        ),
      ...styleFindings.where((Finding finding) => plan.allows(finding.code)),
    ];
    final RulePolicy policy = RulePolicy(config);
    final Set<String> activeYagniRuleIds = RuleCatalog.all
        .where((RuleMetadata metadata) => metadata.group == 'yagni')
        .map((RuleMetadata metadata) => metadata.id)
        .where((String id) => policy.modeFor(id) != RuleMode.off)
        .toSet();
    final List<Finding> all = <Finding>[
      ...base,
      ...const YagniConcentrationAnalysis().findings(
        findings: base,
        activeYagniRuleIds: activeYagniRuleIds,
        config: config,
      ),
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

  List<Finding> _focusedComplexity(
    IndexedAnalysis indexed,
    AnalysisExecutionPlan plan,
  ) => _findingFamily('complexity', () {
    final PreparedAnalysis prepared = indexed.prepared;
    final RepositoryAnalysis repository = RepositoryAnalysis();
    return <Finding>[
          ...repository.complexityFindings(
            functions: _allFunctions(indexed),
            config: prepared.config,
          ),
          ...repository.fileFindings(
            sources: prepared.sources,
            config: prepared.config,
          ),
          ..._allLanguageFindings(indexed),
        ]
        .where((Finding finding) => plan.allows(finding.code))
        .toList(growable: false);
  });

  List<Finding> _focusedDuplication(
    IndexedAnalysis indexed,
    AnalysisExecutionPlan plan,
  ) => _findingFamily('duplication', () {
    final PreparedAnalysis prepared = indexed.prepared;
    final DuplicationAnalysis duplication = DuplicationAnalysis();
    final List<FunctionSource> functions = _allFunctions(indexed);
    return <Finding>[
          ...duplication.exactBlocks(
            prepared.sources,
            minLines: prepared.config.minDuplicationLines,
          ),
          if (prepared.config.duplicationMode != DuplicationMode.exact)
            ...duplication.nearDuplicateFunctions(functions),
          if (prepared.config.duplicationMode == DuplicationMode.semantic)
            ...duplication.parallelContractImplementations(functions),
          ...duplication.repeatedConditions(prepared.sources),
          ..._allLanguageFindings(indexed),
        ]
        .where((Finding finding) => plan.allows(finding.code))
        .toList(growable: false);
  });

  List<FunctionSource> _allFunctions(IndexedAnalysis indexed) =>
      <FunctionSource>[
        ...indexed.require('cpp').functions,
        ...indexed.require('csharp').functions,
        ...indexed.require('dart').functions,
        ...indexed.require('go').functions,
        ...indexed.require('java').functions,
        ...indexed.require('javascript').functions,
        ...indexed.require('nim').functions,
        ...indexed.require('mojo').functions,
        ...indexed.require('wren').functions,
        ...indexed.require('python').functions,
        ...indexed.require('rust').functions,
      ];

  List<Finding> _allLanguageFindings(IndexedAnalysis indexed) => <Finding>[
    ...indexed.require('html').findings,
    ...indexed.require('css').findings,
    ...indexed.require('wren').findings,
    ...indexed.require('nim').findings,
    ...indexed.require('lua').findings,
    ...indexed.require('mojo').findings,
    ...indexed.require('javascript').findings,
    ...indexed.require('go').findings,
    ...indexed.require('python').findings,
    ...indexed.require('sql').findings,
    ...indexed.require('rust').findings,
    ...indexed.require('cpp').findings,
    ...indexed.require('csharp').findings,
    ...indexed.require('java').findings,
    ...indexed.require('dart').findings,
  ];

  List<Finding> _perSourceFamily(
    String name,
    Map<String, String> sources,
    List<Finding> Function(Map<String, String> selected) analyze,
  ) {
    final List<Finding> findings = <Finding>[];
    for (final MapEntry<String, String> source in sources.entries) {
      final Map<String, String> selected = <String, String>{
        source.key: source.value,
      };
      findings.addAll(
        _findingFamily(
          '$name:${source.key}',
          () => analyze(selected),
          sourceInputs: selected,
          timingName: name,
        ),
      );
    }
    return findings;
  }

  List<Finding> _findingFamily(
    String name,
    List<Finding> Function() operation, {
    Map<String, String>? sourceInputs,
    String? timingName,
  }) => _measure(
    timingName ?? name,
    () => _cacheFamily?.call(name, sourceInputs, operation) ?? operation(),
  );

  T _measure<T>(String name, T Function() operation) {
    final Stopwatch stopwatch = Stopwatch()..start();
    final T result = operation();
    _familyTimings[name] =
        (_familyTimings[name] ?? 0) + stopwatch.elapsedMilliseconds;
    return result;
  }
}
