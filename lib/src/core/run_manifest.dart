// A result is only reproducible when it records what was selected, which configuration ran, and whether processing completed cleanly.

import 'schema_versions.dart';

enum RunStatus {
  /// Every selected input and enabled stage completed.
  complete,

  /// Useful results exist, but one or more recoverable diagnostics occurred.
  partial,

  /// Analysis could not produce a trustworthy result.
  failed,
}

extension on RunStatus {
  String get wireValue => switch (this) {
    RunStatus.complete => 'complete',
    RunStatus.partial => 'partial',
    RunStatus.failed => 'failed',
  };
}

final class RunManifest {
  const RunManifest({
    required this.command,
    required this.root,
    required this.gitRevision,
    required this.sourceHash,
    required this.configHash,
    required this.selectedFiles,
    required this.coverage,
    required this.languages,
    required this.languageVersions,
    required this.graphCacheHit,
    required this.findingsCacheHit,
    required this.durationMilliseconds,
    this.status = RunStatus.complete,
  });

  final String command;

  final String root;

  final String? gitRevision;

  final String sourceHash;

  final String configHash;

  final List<String> selectedFiles;

  final Map<String, int> coverage;

  final List<String> languages;

  final Map<String, String> languageVersions;

  final bool graphCacheHit;

  final bool findingsCacheHit;

  final int durationMilliseconds;

  final RunStatus status;

  /// Converts this manifest to its stable machine-readable envelope.
  ///
  /// Selected paths are omitted from compact reports unless [includeFiles] is
  /// requested; their count and aggregate source hash remain available.
  Map<String, Object?> toJson({
    bool includeFiles = true,
    bool includeOperational = true,
  }) => <String, Object?>{
    'schemaVersion': runManifestSchemaVersion,
    'status': status.wireValue,
    'command': command,
    'root': root,
    if (gitRevision != null) 'gitRevision': gitRevision,
    'sourceHash': sourceHash,
    'configHash': configHash,
    'selectedFileCount': selectedFiles.length,
    if (includeFiles) 'selectedFiles': selectedFiles,
    'coverage': coverage,
    'languages': languages,
    if (languageVersions.isNotEmpty) 'languageVersions': languageVersions,
    if (includeOperational)
      'cache': <String, bool>{
        'graphHit': graphCacheHit,
        'findingsHit': findingsCacheHit,
      },
    if (includeOperational) 'durationMilliseconds': durationMilliseconds,
  };
}
