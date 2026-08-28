// Language support plugs into the pipeline through this contract, including shared parse results, functions, graphs, and diagnostics.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:path/path.dart' as p;

import '../core/models.dart';
import '../core/processing_diagnostic.dart';
import '../core/rule.dart';
import '../core/rule_policy.dart';
import '../engine/analysis.dart';
import '../graph/graph.dart';
import '../languages/cpp/cpp_adapter.dart';
import '../languages/csharp/csharp_adapter.dart';
import '../languages/dart/dart_adapter.dart';
import '../languages/go/go_adapter.dart';
import '../languages/java/java_adapter.dart';
import '../languages/javascript/javascript_adapter.dart';
import '../languages/lua/lua_adapter.dart';
import '../languages/mojo/mojo_adapter.dart';
import '../languages/nim/nim_adapter.dart';
import '../languages/python/python_adapter.dart';
import '../languages/rust/rust_adapter.dart';
import '../languages/wren/wren_adapter.dart';
import '../rules/language_rules.dart';
import '../rules/nim/nim_finding_order.dart';

/// Immutable outputs produced by one language plugin invocation.
final class LanguageAnalysis {
  const LanguageAnalysis({
    required this.graph,
    required this.functions,
    required this.findings,
    this.diagnostics = const <ProcessingDiagnostic>[],
    this.representation,
  });

  final DependencyGraph graph;

  final List<FunctionSource> functions;

  final List<Finding> findings;

  final List<ProcessingDiagnostic> diagnostics;

  final Object? representation;
}

/// Language-specific capabilities consumed by the analysis pipeline.
///
/// Plugins isolate registration and adapter selection from the central runner.
/// A later parse-once representation can implement these methods without
/// changing pipeline call sites.
abstract interface class LanguagePlugin {
  String get id;

  Set<String> get sourceLanguageIds;

  LanguageAnalysis analyze(Map<String, String> sources, AnalysisConfig config);

  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  );

  List<FunctionSource> functions(Map<String, String> sources);
}

abstract base class BuiltInLanguagePlugin implements LanguagePlugin {
  const BuiltInLanguagePlugin();

  @override
  Set<String> get sourceLanguageIds => <String>{id};

  @override
  LanguageAnalysis analyze(Map<String, String> sources, AnalysisConfig config) {
    final List<FunctionSource> extractedFunctions = functions(sources);
    return LanguageAnalysis(
      graph: buildGraph(sources, config),
      functions: List<FunctionSource>.unmodifiable(extractedFunctions),
      findings: List<Finding>.unmodifiable(
        executeRegisteredRules(sources, config),
      ),
    );
  }

  RuleRegistry get registeredRules => languageRules(id);

  Iterable<Finding> executeRegisteredRules(
    Map<String, String> sources,
    AnalysisConfig config, {
    Object? representation,
  }) {
    final Map<String, List<String>> sourceLines =
        Map<String, List<String>>.unmodifiable(
          sources.map(
            (String path, String source) =>
                MapEntry<String, List<String>>(path, source.split('\n')),
          ),
        );
    return registeredRules.rules
        .where(
          (CodeBusterRule rule) =>
              config.ruleGroups.contains(rule.metadata.group) ||
              config.ruleGroups.contains(
                RulePolicy.taxonomyGroupFor(rule.metadata.id),
              ) ||
              config.severityOverrides.containsKey(rule.metadata.id),
        )
        .expand(
          (CodeBusterRule rule) => rule.analyze(
            RuleContext(
              config: config,
              sources: sources,
              sourceLines: sourceLines,
              language: id,
              languageAnalysis: representation,
            ),
          ),
        );
  }
}

abstract interface class FindingOrderLanguagePlugin {
  int compareFindings(Finding left, Finding right);
}

final class LanguagePluginRegistry {
  LanguagePluginRegistry(Iterable<LanguagePlugin> plugins)
    : _plugins = Map<String, LanguagePlugin>.unmodifiable(
        _indexPlugins(plugins),
      );

  factory LanguagePluginRegistry.standard() =>
      LanguagePluginRegistry(const <LanguagePlugin>[
        CppLanguagePlugin(),
        CSharpLanguagePlugin(),
        CssLanguagePlugin(),
        DartLanguagePlugin(),
        HtmlLanguagePlugin(),
        GoLanguagePlugin(),
        JavaLanguagePlugin(),
        JavaScriptLanguagePlugin(),
        LuaLanguagePlugin(),
        MojoLanguagePlugin(),
        NimLanguagePlugin(),
        PythonLanguagePlugin(),
        RustLanguagePlugin(),
        SqlLanguagePlugin(),
        WrenLanguagePlugin(),
      ]);

  final Map<String, LanguagePlugin> _plugins;

  Iterable<LanguagePlugin> get plugins => _plugins.values;

  LanguagePlugin? operator [](String id) => _plugins[id.toLowerCase()];

  int compareFindings(String id, Finding left, Finding right) {
    final LanguagePlugin plugin = require(id);
    return plugin is FindingOrderLanguagePlugin
        ? (plugin as FindingOrderLanguagePlugin).compareFindings(left, right)
        : 0;
  }

  LanguagePlugin require(String id) {
    final LanguagePlugin? plugin = this[id];
    if (plugin != null) return plugin;
    throw StateError('No language plugin registered for $id');
  }

  static Map<String, LanguagePlugin> _indexPlugins(
    Iterable<LanguagePlugin> plugins,
  ) {
    final Map<String, LanguagePlugin> indexed = <String, LanguagePlugin>{};
    for (final LanguagePlugin plugin in plugins) {
      final String id = plugin.id.toLowerCase();
      if (indexed.containsKey(id)) {
        throw ArgumentError.value(id, 'plugins', 'duplicate language ID');
      }
      indexed[id] = plugin;
    }
    return indexed;
  }
}

final class CppLanguagePlugin extends BuiltInLanguagePlugin {
  const CppLanguagePlugin();

  static final CppAdapter _adapter = CppAdapter();

  @override
  String get id => 'cpp';

  @override
  Set<String> get sourceLanguageIds => <String>{'cpp', 'objective-c'};

  @override
  Iterable<Finding> executeRegisteredRules(
    Map<String, String> sources,
    AnalysisConfig config, {
    Object? representation,
  }) => super.executeRegisteredRules(
    _sourcesCompiledAsCpp(sources),
    config,
    representation: representation,
  );

  Map<String, String> _sourcesCompiledAsCpp(Map<String, String> sources) {
    final Set<String> explicitCpp = sources.keys
        .where(_hasExplicitCppExtension)
        .toSet();
    if (explicitCpp.isEmpty) {
      return const <String, String>{};
    }

    final bool hasCOrObjectiveC = sources.keys.any(_hasCOrObjectiveCExtension);
    final Set<String> selected = <String>{...explicitCpp};
    if (!hasCOrObjectiveC) {
      // A .h file has no intrinsic dialect. It is safe to treat it as C++
      // only when the analyzed source set has no C or Objective-C unit that
      // may require the header to remain C-compatible.
      selected.addAll(sources.keys.where(_hasAmbiguousHeaderExtension));
    }

    return <String, String>{
      for (final MapEntry<String, String> source in sources.entries)
        if (selected.contains(source.key)) source.key: source.value,
    };
  }

  static bool _hasExplicitCppExtension(String sourcePath) {
    final String extension = p.extension(sourcePath);
    return extension == '.C' ||
        _cppExtensions.contains(extension.toLowerCase());
  }

  static bool _hasCOrObjectiveCExtension(String sourcePath) {
    final String extension = p.extension(sourcePath);
    return extension != '.C' &&
        _cAndObjectiveCExtensions.contains(extension.toLowerCase());
  }

  static bool _hasAmbiguousHeaderExtension(String sourcePath) =>
      _ambiguousHeaderExtensions.contains(
        p.extension(sourcePath).toLowerCase(),
      );

  static const Set<String> _cppExtensions = <String>{
    '.cc',
    '.cpp',
    '.cxx',
    '.c++',
    '.cp',
    '.hh',
    '.hpp',
    '.hxx',
    '.h++',
    '.ipp',
    '.inl',
    '.tpp',
    '.mm',
  };
  static const Set<String> _cAndObjectiveCExtensions = <String>{'.c', '.m'};
  static const Set<String> _ambiguousHeaderExtensions = <String>{'.h'};

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class GoLanguagePlugin extends BuiltInLanguagePlugin {
  const GoLanguagePlugin();

  static final GoAdapter _adapter = GoAdapter();

  @override
  String get id => 'go';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class CSharpLanguagePlugin extends BuiltInLanguagePlugin {
  const CSharpLanguagePlugin();

  static final CSharpAdapter _adapter = CSharpAdapter();

  @override
  String get id => 'csharp';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class CssLanguagePlugin extends BuiltInLanguagePlugin {
  const CssLanguagePlugin();

  @override
  String get id => 'css';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => DependencyGraph(const <String, Iterable<String>>{});

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}

final class HtmlLanguagePlugin extends BuiltInLanguagePlugin {
  const HtmlLanguagePlugin();

  @override
  String get id => 'html';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => DependencyGraph(const <String, Iterable<String>>{});

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}

final class DartLanguagePlugin extends BuiltInLanguagePlugin {
  const DartLanguagePlugin();

  @override
  String get id => 'dart';

  @override
  LanguageAnalysis analyze(Map<String, String> sources, AnalysisConfig config) {
    final DartWorkspaceLayout workspace = DartWorkspaceLayout.discover(
      config.root,
      sources.keys,
    );
    final DartSourceParser parser = DartSourceParser();
    final Map<String, DartParseResult> parsed = <String, DartParseResult>{
      for (final MapEntry<String, String> source in sources.entries)
        source.key: parser.parseDetailed(source.value, sourcePath: source.key),
    };
    final Map<String, CompilationUnit> units =
        Map<String, CompilationUnit>.unmodifiable(<String, CompilationUnit>{
          for (final MapEntry<String, DartParseResult> source in parsed.entries)
            source.key: source.value.unit,
        });
    return LanguageAnalysis(
      graph: DartGraphAdapter(
        root: config.root,
        packageName: '',
        packageLibDirectories: workspace.packageLibDirectories,
      ).buildParsed(sources, units),
      functions: parser.functionsParsed(units),
      // dart format is authoritative and may intentionally emit lines wider
      // than its page width for typed records and fluent expressions.
      findings: <Finding>[
        ...executeRegisteredRules(sources, config, representation: units),
      ],
      diagnostics: _dartProcessingDiagnostics(parsed),
      representation: units,
    );
  }

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) {
    final DartWorkspaceLayout workspace = DartWorkspaceLayout.discover(
      config.root,
      sources.keys,
    );
    return DartGraphAdapter(
      root: config.root,
      packageName: '',
      packageLibDirectories: workspace.packageLibDirectories,
    ).build(sources);
  }

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}

List<ProcessingDiagnostic> _dartProcessingDiagnostics(
  Map<String, DartParseResult> parsed,
) {
  final List<ProcessingDiagnostic> result = <ProcessingDiagnostic>[];
  for (final MapEntry<String, DartParseResult> source in parsed.entries) {
    final Map<String, List<int>> grouped = <String, List<int>>{};
    for (final DartParseDiagnostic diagnostic in source.value.diagnostics) {
      grouped
          .putIfAbsent(diagnostic.message, () => <int>[])
          .add(diagnostic.line);
    }
    final List<String> messages = grouped.keys.toList()..sort();
    for (final String message in messages.take(5)) {
      final List<int> lines = grouped[message]!..sort();
      result.add(
        ProcessingDiagnostic(
          code: 'dart-parse-error',
          severity: ProcessingDiagnosticSeverity.warning,
          stage: 'parsing',
          path: source.key,
          message:
              'line ${lines.first}: $message'
              '${lines.length > 1 ? ' (${lines.length} occurrences)' : ''}',
        ),
      );
    }
    if (messages.length > 5) {
      result.add(
        ProcessingDiagnostic(
          code: 'dart-parse-error-summary',
          severity: ProcessingDiagnosticSeverity.warning,
          stage: 'parsing',
          path: source.key,
          message: '${messages.length - 5} additional parser diagnostic types',
        ),
      );
    }
  }
  return result;
}

final class JavaLanguagePlugin extends BuiltInLanguagePlugin {
  const JavaLanguagePlugin();

  static final JavaAdapter _adapter = JavaAdapter();

  @override
  String get id => 'java';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class JavaScriptLanguagePlugin extends BuiltInLanguagePlugin {
  const JavaScriptLanguagePlugin();

  static final JavaScriptGraphAdapter _graph = JavaScriptGraphAdapter();
  static final JavaScriptFunctionAnalysis _functions =
      JavaScriptFunctionAnalysis();

  @override
  String get id => 'javascript';

  @override
  Set<String> get sourceLanguageIds => <String>{'javascript', 'typescript'};

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _graph.build(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _functions.functions(sources);
}

final class LuaLanguagePlugin extends BuiltInLanguagePlugin {
  const LuaLanguagePlugin();

  static final LuaGraphAdapter _graph = LuaGraphAdapter();

  @override
  String get id => 'lua';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _graph.build(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}

final class MojoLanguagePlugin extends BuiltInLanguagePlugin {
  const MojoLanguagePlugin();

  static final MojoAdapter _adapter = MojoAdapter();

  @override
  String get id => 'mojo';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class NimLanguagePlugin extends BuiltInLanguagePlugin
    implements FindingOrderLanguagePlugin {
  const NimLanguagePlugin();

  static final NimAdapter _adapter = NimAdapter();

  @override
  String get id => 'nim';

  @override
  int compareFindings(Finding left, Finding right) =>
      NimFindingOrder.compare(left, right);

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class PythonLanguagePlugin extends BuiltInLanguagePlugin {
  const PythonLanguagePlugin();

  static final PythonGraphAdapter _graph = PythonGraphAdapter();
  static final PythonFunctionParser _functions = PythonFunctionParser();

  @override
  String get id => 'python';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _graph.build(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _functions.parse(sources);
}

final class RustLanguagePlugin extends BuiltInLanguagePlugin {
  const RustLanguagePlugin();

  static final RustAdapter _adapter = RustAdapter();

  @override
  String get id => 'rust';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}

final class SqlLanguagePlugin extends BuiltInLanguagePlugin {
  const SqlLanguagePlugin();

  @override
  String get id => 'sql';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => DependencyGraph(const <String, Iterable<String>>{});

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      const <FunctionSource>[];
}

final class WrenLanguagePlugin extends BuiltInLanguagePlugin {
  const WrenLanguagePlugin();

  static final WrenAdapter _adapter = WrenAdapter();

  @override
  String get id => 'wren';

  @override
  DependencyGraph buildGraph(
    Map<String, String> sources,
    AnalysisConfig config,
  ) => _adapter.buildGraph(sources);

  @override
  List<FunctionSource> functions(Map<String, String> sources) =>
      _adapter.functions(sources);
}
