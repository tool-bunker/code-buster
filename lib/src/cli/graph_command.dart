// Dependency data has several visual forms, so graph rendering is kept away from the analysis that produces the edges.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/architecture/architecture.dart';

import 'cli_command.dart';

/// Renders dependency graphs and architecture diagrams.
final class GraphCommand implements CliCommandHandler {
  /// Creates the graph command.
  const GraphCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.graph,
  };

  @override
  int execute(CodeBusterCliOptions options) => _graph(options);
}

int _graph(CodeBusterCliOptions options) {
  final AnalysisRun run = AnalysisRunner().run(options);
  if (run.files.isEmpty && !options.allowEmpty) {
    stderr.writeln('no source files found (use --allow-empty to allow this)');
    return 1;
  }
  final List<Map<String, String>> edges = _displayGraphEdges(run);
  if (options.format == ReportFormat.mermaid &&
      run.config.architectureLayers.isNotEmpty) {
    stdout.write(ArchitectureAnalysis(run.graph, run.config).mermaid());
  } else if (options.format == ReportFormat.mermaid) {
    stdout.writeln('flowchart LR');
    final Map<String, String> identifiers = <String, String>{};
    var index = 0;
    for (final String node in run.graph.nodes.toList()..sort()) {
      final String id = 'n${index++}';
      identifiers[node] = id;
      stdout.writeln('  $id["${node.replaceAll('"', '&quot;')}"]');
    }
    for (final Map<String, String> edge in edges) {
      stdout.writeln(
        '  ${identifiers[edge['source']]} --> ${identifiers[edge['target']]}',
      );
    }
  } else if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'version': 1,
        'command': 'graph',
        'root': run.config.root,
        'files': run.files.length,
        'edges': edges,
      }),
    );
  } else {
    stdout.writeln('Code Buster graph: ${run.files.length} files');
    for (final Map<String, String> edge in edges) {
      stdout.writeln('${edge['source']} -> ${edge['target']}');
    }
  }
  return 0;
}

List<Map<String, String>> _displayGraphEdges(AnalysisRun run) {
  final List<Map<String, String>> edges = <Map<String, String>>[];
  for (final SourceFile file in run.files) {
    final String source = file.relativePath;
    if (file.language == 'dart') {
      for (final RegExpMatch match in RegExp(
        r'''^\s*(?:import|export)\s+["']([^"']+)["']\s*;''',
        multiLine: true,
      ).allMatches(run.sources[source]!)) {
        edges.add(<String, String>{'source': source, 'target': ';'});
        edges.add(<String, String>{
          'source': source,
          'target': match.group(1)!,
        });
      }
    } else if (file.language == 'cpp') {
      for (final RegExpMatch match in RegExp(
        r'''^\s*#\s*include\s*[<"]([^>"]+)[>"]''',
        multiLine: true,
      ).allMatches(run.sources[source]!)) {
        edges.add(<String, String>{
          'source': source,
          'target': match.group(1)!,
        });
      }
    } else if (file.language == 'python') {
      for (final String raw in run.sources[source]!.split('\n')) {
        final String line = raw.trim();
        if (line.startsWith('import ')) {
          for (final String module in line.substring(7).split(',')) {
            edges.add(<String, String>{
              'source': source,
              'target': module.trim().split(' ').first,
            });
          }
        } else if (line.startsWith('from ') && line.contains(' import ')) {
          edges.add(<String, String>{
            'source': source,
            'target': line.substring(5, line.indexOf(' import ')).trim(),
          });
        }
      }
    } else if (file.language == 'nim') {
      for (final String raw in run.sources[source]!.split('\n')) {
        final String line = raw.trim();
        if (line.startsWith('import ')) {
          final String body = line.substring(7);
          final int groupOpen = body.indexOf('[');
          final int groupClose = body.lastIndexOf(']');
          final Iterable<String> modules =
              groupOpen < 0 || groupClose <= groupOpen
              ? body.split(',')
              : body
                    .substring(groupOpen + 1, groupClose)
                    .split(',')
                    .map(
                      (String item) =>
                          '${body.substring(0, groupOpen)}${item.trim()}',
                    );
          for (final String module in modules) {
            String target = module.trim().split(' ').first;
            if (target.startsWith('../src/')) {
              target = target.substring(target.lastIndexOf('/') + 1);
            }
            edges.add(<String, String>{'source': source, 'target': target});
          }
        } else if (line.startsWith('from ') && line.contains(' import ')) {
          edges.add(<String, String>{
            'source': source,
            'target': line.substring(5, line.indexOf(' import ')).trim(),
          });
        }
      }
    } else if (file.language == 'javascript' || file.language == 'typescript') {
      for (final String raw in run.sources[source]!.split('\n')) {
        final String line = raw.trim();
        if (line.startsWith('import ') || line.startsWith('export ')) {
          for (final RegExpMatch match in RegExp(
            r'''["']([^"']+)["']''',
          ).allMatches(line)) {
            edges.add(<String, String>{
              'source': source,
              'target': match.group(1)!,
            });
          }
        }
      }
    } else {
      for (final String target in run.graph.dependenciesOf(source)) {
        edges.add(<String, String>{'source': source, 'target': target});
      }
    }
  }
  edges.sort((Map<String, String> left, Map<String, String> right) {
    final int source = left['source']!.compareTo(right['source']!);
    return source != 0 ? source : left['target']!.compareTo(right['target']!);
  });
  return edges;
}
