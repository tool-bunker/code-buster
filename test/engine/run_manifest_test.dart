import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  test('records deterministic inputs coverage and cache reuse', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-manifest-');
    addTearDown(() => root.deleteSync(recursive: true));
    File(path.join(root.path, 'lib', 'main.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void main() {}\n');
    final options = CodeBusterCliContract.parse(<String>[
      'summary',
      '--root',
      root.path,
    ]);

    final AnalysisRun first = AnalysisRunner().run(options);
    final AnalysisRun second = AnalysisRunner().run(options);
    final RunManifest manifest = second.manifest!;

    expect(first.manifest!.graphCacheHit, isFalse);
    expect(first.manifest!.findingsCacheHit, isFalse);
    expect(manifest.graphCacheHit, isTrue);
    expect(manifest.findingsCacheHit, isTrue);
    expect(manifest.selectedFiles, <String>['lib/main.dart']);
    expect(manifest.coverage['selected'], 1);
    expect(manifest.languages, <String>['dart']);
    expect(manifest.sourceHash, hasLength(64));
    expect(manifest.configHash, hasLength(64));
    expect(manifest.status, RunStatus.complete);
    expect(manifest.toJson()['schemaVersion'], runManifestSchemaVersion);

    final Map<String, Object?> report =
        jsonDecode(
              FindingReporter().render(
                format: ReportFormat.json,
                command: 'summary',
                root: root.path,
                files: second.files.length,
                findings: second.findings,
                manifest: manifest,
              ),
            )
            as Map<String, Object?>;
    final Map<String, Object?> compactManifest =
        report['manifest']! as Map<String, Object?>;
    expect(compactManifest['sourceHash'], manifest.sourceHash);
    expect(compactManifest['selectedFileCount'], 1);
    expect(compactManifest, isNot(contains('selectedFiles')));
  });

  test('reports recovered parser diagnostics separately from findings', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-parse-');
    addTearDown(() => root.deleteSync(recursive: true));
    File(
      path.join(root.path, 'broken.dart'),
    ).writeAsStringSync('void main( {\n');

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(run.manifest!.status, RunStatus.partial);
    expect(
      run.diagnostics.map((ProcessingDiagnostic item) => item.code),
      contains('dart-parse-error'),
    );
    expect(
      run.diagnostics.every(
        (ProcessingDiagnostic item) => item.stage == 'parsing',
      ),
      isTrue,
    );
  });

  test('marks recoverable source decoding damage as partial', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-partial-');
    addTearDown(() => root.deleteSync(recursive: true));
    File(path.join(root.path, 'legacy.js')).writeAsBytesSync(<int>[
      ...'const value = "'.codeUnits,
      0x96,
      ...'";\n'.codeUnits,
    ]);

    final AnalysisRun run = AnalysisRunner().run(
      CodeBusterCliContract.parse(<String>['summary', '--root', root.path]),
    );

    expect(run.manifest!.status, RunStatus.partial);
    expect(run.manifest!.toJson()['status'], 'partial');
    expect(run.diagnostics.single.code, 'malformed-utf8');
    expect(run.findings, isNot(contains(run.diagnostics.single)));

    final Map<String, Object?> report =
        jsonDecode(
              FindingReporter().render(
                format: ReportFormat.json,
                command: 'summary',
                root: root.path,
                files: run.files.length,
                findings: run.findings,
                manifest: run.manifest,
                diagnostics: run.diagnostics,
              ),
            )
            as Map<String, Object?>;
    final List<Object?> diagnostics =
        report['processingDiagnostics']! as List<Object?>;
    expect(
      (diagnostics.single! as Map<String, Object?>)['stage'],
      'source-decoding',
    );
  });
}
