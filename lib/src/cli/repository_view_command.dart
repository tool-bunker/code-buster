// Inspect, related, why, and path are different views over one dependency graph and should agree on navigation semantics.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Handles source inspection and dependency navigation commands.
final class RepositoryViewCommand implements CliCommandHandler {
  /// Creates the repository view command.
  const RepositoryViewCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.inspect,
    CodeBusterCommand.related,
    CodeBusterCommand.why,
    CodeBusterCommand.path,
  };

  @override
  int execute(CodeBusterCliOptions options) => switch (options.command) {
    CodeBusterCommand.inspect => _inspect(options),
    CodeBusterCommand.related => _related(options),
    CodeBusterCommand.why => _why(options),
    CodeBusterCommand.path => _path(options),
    _ => throw StateError('unsupported repository view command'),
  };
}

int _inspect(CodeBusterCliOptions options) {
  final String? target = options.target;
  if (target == null || target.isEmpty) {
    stderr.writeln('inspect requires a project-relative source path');
    return 64;
  }
  final String normalized = target.replaceAll('\\', '/');
  final AnalysisConfig projectConfig = CodeBusterConfigLoader.loadFromRoot(
    Directory(options.root).absolute.path,
  );
  String? matchedOverride;
  String classification = RepositoryDefaults.classify(normalized);
  for (final MapEntry<String, List<String>> override in <String, List<String>>{
    'production': projectConfig.classificationProduction,
    'test': projectConfig.classificationTest,
    'generated': projectConfig.classificationGenerated,
  }.entries) {
    for (final String pattern in override.value) {
      if (RepositoryDefaults.matches(normalized, pattern)) {
        classification = override.key;
        matchedOverride = pattern;
      }
    }
  }
  final String classificationSource = matchedOverride == null
      ? 'built-in language/framework defaults'
      : 'code-buster.toml';
  final bool categoryIncluded =
      classification != 'generated' &&
      (options.includeAll ||
          classification == 'production' ||
          (classification == 'test' && options.includeTests) ||
          (classification == 'example' && options.includeExamples) ||
          (classification == 'vendored' && options.includeVendored));
  final File targetFile = File(
    '${Directory(options.root).absolute.path}${Platform.pathSeparator}${normalized.replaceAll('/', Platform.pathSeparator)}',
  );
  if (targetFile.existsSync() && !categoryIncluded) {
    if (options.format == ReportFormat.json) {
      stdout.writeln(
        jsonEncode(<String, Object>{
          'path': normalized,
          'classification': classification,
          'classification_source': classificationSource,
          'matched': ?matchedOverride,
          'included': false,
          'reason': 'excluded by the default production scope',
          'override': switch (classification) {
            'test' => '--include-tests',
            'example' => '--include-examples',
            'vendored' => '--include-vendored',
            _ => '--all',
          },
        }),
      );
    } else {
      stdout.writeln('path=$normalized');
      stdout.writeln('classification=$classification');
      stdout.writeln('classification_source=$classificationSource');
      if (matchedOverride != null) stdout.writeln('matched=$matchedOverride');
      stdout.writeln('included=false');
      stdout.writeln('reason=excluded by the default production scope');
    }
    return 0;
  }
  final AnalysisRun run = AnalysisRunner().run(
    options,
    command: CodeBusterCommand.summary,
  );
  if (!run.sources.containsKey(normalized)) {
    stderr.writeln('target is not a discovered source file: $target');
    return 1;
  }
  final List<Finding> findings = run.findings
      .where((Finding item) => item.path == normalized)
      .toList(growable: false);
  if (options.format == ReportFormat.json) {
    final SourceFile file = run.files.firstWhere(
      (SourceFile item) => item.relativePath == normalized,
    );
    final String source = run.sources[normalized]!;
    final List<String> imports = <String>[];
    final List<String> exports = <String>[];
    final List<Object> functions = <Object>[];
    if (file.language == 'dart') {
      final DartSourceParser adapter = DartSourceParser();
      final unit = adapter.parseCompilationUnit(source, sourcePath: normalized);
      final units = {normalized: unit};
      final DartUnit summary = adapter.summarize(unit);
      imports.addAll(<String>[...summary.imports, ...summary.exports]);
      exports.addAll(summary.publicDeclarations);
      functions.addAll(
        adapter
            .functionsParsed(units)
            .map(
              (FunctionSource function) => <String, Object>{
                'name': function.name,
                'line': function.line,
              },
            ),
      );
    } else {
      imports.addAll(run.graph.dependenciesOf(normalized));
    }
    final List<String> importedBy =
        run.graph.nodes
            .where(
              (String node) =>
                  run.graph.dependenciesOf(node).contains(normalized),
            )
            .toList()
          ..sort();
    stdout.writeln(
      jsonEncode(<String, Object>{
        'path': normalized,
        'classification': classification,
        'classification_source': classificationSource,
        'matched': ?matchedOverride,
        'included': true,
        'language': file.language,
        'lines': source.split('\n').length,
        'imports': imports,
        'imported_by': importedBy,
        'exports': exports,
        'flags': findings
            .where((Finding finding) => finding.code == 'feature-flag')
            .map((Finding finding) => finding.message.split(': ').last)
            .toList(growable: false),
        'functions': functions,
        'findings': findings
            .map(
              (Finding finding) =>
                  '${finding.code}:${finding.line} ${finding.message}',
            )
            .toList(growable: false),
      }),
    );
  } else {
    stdout.writeln('classification=$classification');
    stdout.writeln('classification_source=$classificationSource');
    if (matchedOverride != null) stdout.writeln('matched=$matchedOverride');
    stdout.writeln('included=true');
    stdout.writeln(
      FindingReporter().render(
        format: options.format,
        command: 'inspect',
        root: run.config.root,
        files: 1,
        findings: findings,
        languageSummary: run.languageSummary,
        verbose: options.verbose,
      ),
    );
  }
  return options.failOnIssues && findings.isNotEmpty ? 2 : 0;
}

int _related(CodeBusterCliOptions options) {
  final String? target = options.target;
  if (target == null || target.isEmpty) {
    stderr.writeln('related requires a project-relative source path');
    return 64;
  }
  final AnalysisRun run = AnalysisRunner().run(options);
  final String normalized = target.replaceAll('\\', '/');
  if (!run.graph.nodes.contains(normalized)) {
    stderr.writeln('target is not a discovered source file: $target');
    return 1;
  }
  final List<String> dependsOn = run.graph.dependenciesOf(normalized);
  final List<String> dependedOnBy =
      run.graph.nodes
          .where(
            (String node) =>
                run.graph.dependenciesOf(node).contains(normalized),
          )
          .toList()
        ..sort();
  final List<String> related = <String>{...dependsOn, ...dependedOnBy}.toList()
    ..sort();
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'path': normalized,
        'depends_on': dependsOn,
        'depended_on_by': dependedOnBy,
      }),
    );
  } else {
    stdout.writeln('Code Buster related: $normalized');
    for (final String path in related) {
      stdout.writeln(path);
    }
  }
  return 0;
}

int _why(CodeBusterCliOptions options) {
  final String? target = options.target;
  if (target == null || target.isEmpty) {
    stderr.writeln('why requires a project-relative source path');
    return 64;
  }
  final AnalysisRun run = AnalysisRunner().run(options);
  final String normalized = target.replaceAll('\\', '/');
  final GraphAnalysis analysis = GraphAnalysis(run.graph);
  final List<String> roots =
      analysis.defaultRoots(run.config.entryPoints).toList()..sort();
  List<String> path = const <String>[];
  for (final String root in roots) {
    final List<String> candidate = analysis.shortestPath(root, normalized);
    if (candidate.isNotEmpty &&
        (path.isEmpty || candidate.length < path.length)) {
      path = candidate;
    }
  }
  if (path.isEmpty) {
    stderr.writeln('no dependency path reaches: $target');
    return 1;
  }
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{
        'target': normalized,
        'reachable': true,
        'path': path,
      }),
    );
  } else {
    stdout.writeln(path.join(' -> '));
  }
  return 0;
}

int _path(CodeBusterCliOptions options) {
  if (options.targets.length != 2) {
    stderr.writeln('path requires FROM and TO project-relative source paths');
    return 64;
  }
  final AnalysisRun run = AnalysisRunner().run(options);
  final String from = options.targets[0].replaceAll('\\', '/');
  final String to = options.targets[1].replaceAll('\\', '/');
  final List<String> path = GraphAnalysis(run.graph).shortestPath(from, to);
  if (path.isEmpty) {
    stderr.writeln('no dependency path from $from to $to');
    return 1;
  }
  if (options.format == ReportFormat.json) {
    stdout.writeln(
      jsonEncode(<String, Object>{'from': from, 'to': to, 'path': path}),
    );
  } else {
    stdout.writeln(path.join(' -> '));
  }
  return 0;
}
