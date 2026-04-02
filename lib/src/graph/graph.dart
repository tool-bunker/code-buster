// Reachability, reverse edges, paths, and cycles all depend on the same normalized dependency graph representation.

import 'dart:collection';

import '../core/models.dart';

/// Immutable directed dependency graph using project-relative node identifiers.
final class DependencyGraph {
  /// Creates a graph with optional narrower edges for cycle detection.
  DependencyGraph(
    Map<String, Iterable<String>> edges, {
    Map<String, Iterable<String>>? cycleEdges,
  }) : _edges = _freeze(edges),
       _cycleEdges = _freeze(cycleEdges ?? edges),
       _nodes = _collectNodes(edges) {
    for (final String node in _nodes) {
      _edges.putIfAbsent(node, () => const <String>[]);
    }
  }

  final Map<String, List<String>> _edges;
  final Map<String, List<String>> _cycleEdges;
  final Set<String> _nodes;

  /// Every known project-relative graph node.
  Set<String> get nodes => Set<String>.unmodifiable(_nodes);

  /// Returns sorted direct dependencies for [node].
  List<String> dependenciesOf(String node) =>
      List<String>.unmodifiable(_edges[node] ?? const <String>[]);

  /// Returns sorted load-time dependencies used for cycle analysis.
  ///
  /// This can be narrower than [dependenciesOf] for languages such as Lua,
  /// where function-local lazy imports remain reachable dependencies but do not
  /// participate in module initialization cycles.
  List<String> cycleDependenciesOf(String node) =>
      List<String>.unmodifiable(_cycleEdges[node] ?? const <String>[]);

  static Map<String, List<String>> _freeze(
    Map<String, Iterable<String>> edges,
  ) {
    final Map<String, List<String>> result = <String, List<String>>{};
    edges.forEach((String node, Iterable<String> targets) {
      final List<String> sorted =
          targets.where((String target) => target != node).toSet().toList()
            ..sort();
      result[node] = sorted;
    });
    return result;
  }

  static Set<String> _collectNodes(Map<String, Iterable<String>> edges) =>
      Set<String>.unmodifiable(<String>{
        ...edges.keys,
        ...edges.values.expand((Iterable<String> targets) => targets),
      });
}

/// Language-neutral reachability, cycle, and dead-file analysis over a graph.
final class GraphAnalysis {
  /// Creates graph analysis for [graph].
  const GraphAnalysis(this.graph);

  /// Dependency graph under analysis.
  final DependencyGraph graph;

  /// Returns all nodes reachable from [roots], including the roots themselves.
  Set<String> reachableFrom(Iterable<String> roots) {
    final Set<String> reachable = <String>{};
    final Queue<String> pending = Queue<String>.from(
      roots.where(graph.nodes.contains),
    );
    while (pending.isNotEmpty) {
      final String node = pending.removeFirst();
      if (!reachable.add(node)) {
        continue;
      }
      pending.addAll(graph.dependenciesOf(node));
    }
    return Set<String>.unmodifiable(reachable);
  }

  /// Selects configured roots, then `main`, then the first sorted graph node.
  Set<String> defaultRoots(Iterable<String> configuredEntryPoints) {
    final Set<String> configured = configuredEntryPoints
        .where(graph.nodes.contains)
        .toSet();
    if (configured.isNotEmpty) {
      return Set<String>.unmodifiable(configured);
    }
    final Set<String> mains = graph.nodes
        .where((String node) => _stem(node) == 'main')
        .toSet();
    if (mains.isNotEmpty) {
      return Set<String>.unmodifiable(mains);
    }
    final List<String> sorted = graph.nodes.toList()..sort();
    return sorted.isEmpty
        ? const <String>{}
        : Set<String>.unmodifiable(<String>{sorted.first});
  }

  /// Returns the shortest dependency path from [start] to [goal].
  List<String> shortestPath(String start, String goal) {
    if (!graph.nodes.contains(start) || !graph.nodes.contains(goal)) {
      return const <String>[];
    }
    final Queue<List<String>> pending = Queue<List<String>>()
      ..add(<String>[start]);
    final Set<String> visited = <String>{start};
    while (pending.isNotEmpty) {
      final List<String> path = pending.removeFirst();
      final String node = path.last;
      if (node == goal) {
        return List<String>.unmodifiable(path);
      }
      for (final String dependency in graph.dependenciesOf(node)) {
        if (visited.add(dependency)) {
          pending.add(<String>[...path, dependency]);
        }
      }
    }
    return const <String>[];
  }

  /// Finds each directed cycle once, using a sorted-node key for stability.
  List<List<String>> cycles() {
    final Set<String> visiting = <String>{};
    final Set<String> visited = <String>{};
    final List<String> stack = <String>[];
    final Set<String> emitted = <String>{};
    final List<List<String>> result = <List<String>>[];

    void visit(String node) {
      if (visiting.contains(node)) {
        final int index = stack.indexOf(node);
        if (index >= 0) {
          final List<String> cycle = <String>[...stack.sublist(index), node];
          final List<String> canonical = cycle.sublist(0, cycle.length - 1)
            ..sort();
          final String key = canonical.join('|');
          if (emitted.add(key)) {
            result.add(List<String>.unmodifiable(cycle));
          }
        }
        return;
      }
      if (!visited.add(node)) {
        return;
      }
      visiting.add(node);
      stack.add(node);
      for (final String dependency in graph.cycleDependenciesOf(node)) {
        visit(dependency);
      }
      stack.removeLast();
      visiting.remove(node);
    }

    final List<String> nodes = graph.nodes.toList()..sort();
    for (final String node in nodes) {
      visit(node);
    }
    return List<List<String>>.unmodifiable(result);
  }

  /// Emits one representative finding per strongly connected component.
  List<Finding> cycleFindings() => _cyclicComponents()
      // C# has project/assembly boundaries rather than file modules. Mutual
      // type references between files are routine and not import cycles.
      .where(
        (Set<String> component) =>
            !component.every((String path) => path.endsWith('.cs')),
      )
      .map((Set<String> component) {
        final List<String> cycle = _representativeCycle(component);
        final bool moduleCycle = component.every(
          (String path) => RegExp(r'\.(?:dart|js|jsx|ts|tsx)$').hasMatch(path),
        );
        final List<String> represented = cycle.toSet().toList();
        final List<String> additional =
            component
                .where((String path) => !represented.contains(path))
                .toList()
              ..sort();
        final List<String> basenames = cycle.map(_basename).toList();
        final bool ambiguousNames =
            basenames.toSet().length < cycle.take(cycle.length - 1).length;
        final String cycleDescription = ambiguousNames
            ? cycle.join(' -> ')
            : basenames.join(' -> ');
        final String sizeDetail = component.length > represented.length
            ? ' (${component.length} modules in strongly connected component)'
            : '';
        return Finding(
          code: 'cycle',
          severity: moduleCycle ? RuleSeverity.warn : RuleSeverity.error,
          path: cycle.first,
          line: 1,
          endLine: 1,
          message: 'circular dependency: $cycleDescription$sizeDetail',
          confidence: moduleCycle ? 'medium' : 'high',
          relatedFiles: additional.take(20).toList(growable: false),
        );
      })
      .toList(growable: false);

  List<Set<String>> _cyclicComponents() {
    var nextIndex = 0;
    final Map<String, int> indices = <String, int>{};
    final Map<String, int> lowLinks = <String, int>{};
    final List<String> stack = <String>[];
    final Set<String> onStack = <String>{};
    final List<Set<String>> result = <Set<String>>[];

    void connect(String node) {
      indices[node] = nextIndex;
      lowLinks[node] = nextIndex;
      nextIndex++;
      stack.add(node);
      onStack.add(node);
      for (final String target
          in graph.cycleDependenciesOf(node).toList()..sort()) {
        if (!indices.containsKey(target)) {
          connect(target);
          lowLinks[node] = lowLinks[node]!.compareTo(lowLinks[target]!) <= 0
              ? lowLinks[node]!
              : lowLinks[target]!;
        } else if (onStack.contains(target)) {
          lowLinks[node] = lowLinks[node]!.compareTo(indices[target]!) <= 0
              ? lowLinks[node]!
              : indices[target]!;
        }
      }
      if (lowLinks[node] != indices[node]) return;
      final Set<String> component = <String>{};
      while (stack.isNotEmpty) {
        final String member = stack.removeLast();
        onStack.remove(member);
        component.add(member);
        if (member == node) break;
      }
      final bool selfCycle =
          component.length == 1 &&
          graph.dependenciesOf(component.single).contains(component.single);
      if (component.length > 1 || selfCycle) result.add(component);
    }

    for (final String node in graph.nodes.toList()..sort()) {
      if (!indices.containsKey(node)) connect(node);
    }
    result.sort(
      (Set<String> left, Set<String> right) => (left.toList()..sort()).first
          .compareTo((right.toList()..sort()).first),
    );
    return result;
  }

  List<String> _representativeCycle(Set<String> component) {
    final List<String> stack = <String>[];
    final Set<String> visiting = <String>{};
    List<String>? found;
    bool visit(String node) {
      stack.add(node);
      visiting.add(node);
      for (final String target in graph.dependenciesOf(node).toList()..sort()) {
        if (!component.contains(target)) continue;
        final int start = stack.indexOf(target);
        if (start >= 0) {
          found = <String>[...stack.sublist(start), target];
          return true;
        }
        if (!visiting.contains(target) && visit(target)) return true;
      }
      stack.removeLast();
      visiting.remove(node);
      return false;
    }

    for (final String node in component.toList()..sort()) {
      stack.clear();
      visiting.clear();
      if (visit(node)) return found!;
    }
    return <String>[component.first, component.first];
  }

  /// Emits dead-file findings for [eligibleNodes] unreachable from [roots].
  List<Finding> deadFileFindings({
    required Iterable<String> roots,
    required Iterable<String> eligibleNodes,
  }) {
    final Set<String> eligible = eligibleNodes
        .where(graph.nodes.contains)
        .toSet();
    if (eligible.length <= 1) {
      return const <Finding>[];
    }
    final Set<String> reachable = reachableFrom(roots);
    // Reachability is only meaningful when a configured or inferred root
    // reaches the kind of file being checked. In mixed-language repositories,
    // a root from another language must not make every eligible file look dead.
    if (!eligible.any(reachable.contains)) {
      return const <Finding>[];
    }
    final List<String> dead =
        eligible.where((String node) => !reachable.contains(node)).toList()
          ..sort();
    return dead
        .map(
          (String node) => Finding(
            code: 'dead-file',
            severity: RuleSeverity.error,
            path: node,
            line: 1,
            endLine: 1,
            message: 'file is not reachable from configured entry points',
            confidence: 'high',
            why:
                'The file is not reachable from the static dependency graph and configured entry points.',
            suggestion:
                'Remove the file, connect it from reachable code, or configure an entry point.',
          ),
        )
        .toList(growable: false);
  }

  static String _basename(String node) => node.split('/').last;

  static String _stem(String node) {
    final String base = _basename(node);
    final int extension = base.lastIndexOf('.');
    return extension < 0 ? base : base.substring(0, extension);
  }
}
