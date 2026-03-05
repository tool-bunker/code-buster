// Layer rules, forbidden dependencies, and cycles are repository policies over graph edges rather than language-specific syntax checks.

import '../../core/models.dart';
import '../../graph/graph.dart';

/// Enforces configured architecture layers over a resolved source graph.
final class ArchitectureAnalysis {
  /// Creates analysis for [graph] and [config].
  const ArchitectureAnalysis(this.graph, this.config);

  /// Resolved source dependency graph.
  final DependencyGraph graph;

  /// Effective architecture policy.
  final AnalysisConfig config;

  /// Returns cross-layer edges in stable source/target order.
  Map<String, List<String>> layerEdges() {
    final Map<String, Set<String>> mutable = <String, Set<String>>{};
    for (final String source in graph.nodes.toList()..sort()) {
      final String? sourceLayer = layerFor(source);
      if (sourceLayer == null) continue;
      for (final String target in graph.dependenciesOf(source)) {
        final String? targetLayer = layerFor(target);
        if (targetLayer != null && targetLayer != sourceLayer) {
          mutable.putIfAbsent(sourceLayer, () => <String>{}).add(targetLayer);
        }
      }
    }
    return <String, List<String>>{
      for (final String source in mutable.keys.toList()..sort())
        source: mutable[source]!.toList()..sort(),
    };
  }

  /// Finds the first ordered layer pattern matching [sourcePath].
  String? layerFor(String sourcePath) {
    final List<String> segments = sourcePath.replaceAll('\\', '/').split('/');
    final Set<String> segmentSet = segments.toSet();
    for (final String layer in config.architectureLayers) {
      final List<String> pattern = layer.split('/');
      if (pattern.length == 1 && segmentSet.contains(layer)) return layer;
      for (var start = 0; start + pattern.length <= segments.length; start++) {
        var matches = true;
        for (var index = 0; index < pattern.length; index++) {
          if (pattern[index] != '*' &&
              pattern[index] != segments[start + index]) {
            matches = false;
            break;
          }
        }
        if (matches) return layer;
      }
    }
    return null;
  }

  /// Emits forbidden boundary and layer-cycle findings.
  List<Finding> findings() {
    if (config.architectureLayers.isEmpty) return const <Finding>[];
    final Set<String> allowed = config.architectureAllowedDependencies.toSet();
    final Set<String> denied = config.architectureDeniedDependencies.toSet();
    final List<Finding> result = <Finding>[];
    for (final String source in graph.nodes.toList()..sort()) {
      final String? sourceLayer = layerFor(source);
      if (sourceLayer == null) continue;
      for (final String target in graph.dependenciesOf(source)) {
        final String? targetLayer = layerFor(target);
        if (targetLayer == null || targetLayer == sourceLayer) continue;
        final String edge = '$sourceLayer -> $targetLayer';
        if (denied.contains(edge) || !allowed.contains(edge)) {
          result.add(
            Finding(
              code: 'architecture-forbidden-dependency',
              severity: RuleSeverity.error,
              path: source,
              line: 1,
              endLine: 1,
              message: 'forbidden architecture dependency $edge',
              confidence: 'high',
              why: denied.contains(edge)
                  ? 'The module graph crosses an explicitly denied layer boundary.'
                  : 'The module graph crosses a layer boundary that is not explicitly allowed.',
              suggestion:
                  'Move or invert the dependency, or update intentional policy.',
              relatedFiles: <String>[target],
            ),
          );
        }
      }
    }
    result.addAll(_cycleFindings());
    return result;
  }

  List<Finding> _cycleFindings() {
    final Map<String, List<String>> edges = layerEdges();
    final Set<String> visited = <String>{};
    final Set<String> visiting = <String>{};
    final Set<String> emitted = <String>{};
    final List<String> stack = <String>[];
    final List<Finding> result = <Finding>[];
    void visit(String layer) {
      if (visiting.contains(layer)) {
        final int start = stack.indexOf(layer);
        if (start >= 0) {
          final List<String> cycle = <String>[...stack.sublist(start), layer];
          final String key = (cycle.sublist(
            0,
            cycle.length - 1,
          )..sort()).join('|');
          if (emitted.add(key)) {
            result.add(
              Finding(
                code: 'architecture-layer-cycle',
                severity: RuleSeverity.error,
                path: 'code-buster.toml',
                line: 1,
                endLine: 1,
                message: 'architecture layer cycle: ${cycle.join(' -> ')}',
                confidence: 'high',
                why:
                    'Layer cycles make dependency direction and ownership ambiguous.',
                suggestion:
                    'Invert or extract one dependency so the layer graph is acyclic.',
              ),
            );
          }
        }
        return;
      }
      if (!visited.add(layer)) return;
      visiting.add(layer);
      stack.add(layer);
      for (final String target in edges[layer] ?? const <String>[]) {
        visit(target);
      }
      stack.removeLast();
      visiting.remove(layer);
    }

    for (final String layer in config.architectureLayers) {
      visit(layer);
    }
    return result;
  }

  /// Renders the configured layer graph as Mermaid.
  String mermaid() {
    final StringBuffer output = StringBuffer('graph TD\n');
    layerEdges().forEach((String source, List<String> targets) {
      for (final String target in targets) {
        output.writeln('  "$source" --> "$target"');
      }
    });
    return output.toString();
  }
}
