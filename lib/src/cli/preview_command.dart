// Preview shows exactly what discovery would select while guaranteeing that rules and caches are not touched.

import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';

import 'cli_command.dart';

/// Previews deterministic discovery without rule execution or cache mutation.
final class PreviewCommand implements CliCommandHandler {
  /// Creates the stateless handler.
  const PreviewCommand();

  @override
  Set<CodeBusterCommand> get commands => const <CodeBusterCommand>{
    CodeBusterCommand.preview,
  };

  @override
  int execute(CodeBusterCliOptions options) {
    final PreparedAnalysis prepared = AnalysisPreparationStage().prepare(
      options,
    );
    final List<SourceFile> files = prepared.files.toList(growable: false)
      ..sort(
        (SourceFile left, SourceFile right) =>
            left.relativePath.compareTo(right.relativePath),
      );
    if (options.format == ReportFormat.json) {
      stdout.writeln(
        jsonEncode(<String, Object>{
          'schemaVersion': reportSchemaVersion,
          'command': 'preview',
          'root': prepared.root,
          'files': <Map<String, String>>[
            for (final SourceFile file in files)
              <String, String>{
                'path': file.relativePath,
                'language': file.language,
              },
          ],
          'coverage': prepared.coverage,
          if (prepared.languageVersions.isNotEmpty)
            'languageVersions': prepared.languageVersions,
          if (options.verbose && prepared.generatedProvenance.isNotEmpty)
            'generatedProvenance': prepared.generatedProvenance
                .map(
                  (GeneratedSourceProvenance provenance) => provenance.toJson(),
                )
                .toList(growable: false),
          if (prepared.diagnostics.isNotEmpty)
            'processingDiagnostics': prepared.diagnostics
                .map((ProcessingDiagnostic diagnostic) => diagnostic.toJson())
                .toList(growable: false),
        }),
      );
      return 0;
    }
    if (options.format != ReportFormat.text) {
      stderr.writeln('preview supports text and json formats');
      return 2;
    }
    stdout.writeln('Code Buster preview: ${files.length} selected files');
    final List<String> reasons = prepared.coverage.keys.toList()..sort();
    if (reasons.isNotEmpty) {
      stdout.writeln(
        'coverage: ${reasons.map((String reason) => '$reason=${prepared.coverage[reason]}').join(' ')}',
      );
    }
    for (final SourceFile file in files) {
      stdout.writeln('${file.language}\t${file.relativePath}');
    }
    if (options.verbose) {
      for (final GeneratedSourceProvenance provenance
          in prepared.generatedProvenance) {
        stdout.writeln(
          'generated\t${provenance.path}\t${provenance.reason}\t${provenance.source}',
        );
      }
    }
    return 0;
  }
}
