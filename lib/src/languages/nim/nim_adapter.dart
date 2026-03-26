// Nim’s imports, includes, pragmas, and procedures need a dedicated parser before the large compatibility rule pack can evaluate them.

import '../../engine/analysis.dart';
import '../../graph/graph.dart';
import 'nim_dependency_analyzer.dart';
import 'nim_function_parser.dart';

/// Resolves Nim modules and extracts procedures for repository analysis.
final class NimAdapter {
  /// Builds a local dependency graph from Nim import/include/from directives.
  DependencyGraph buildGraph(Map<String, String> sources) =>
      NimDependencyAnalyzer().build(sources);

  /// Extracts indentation-delimited proc/func/method/iterator bodies.
  List<FunctionSource> functions(Map<String, String> sources) =>
      NimFunctionParser().parse(sources);
}
