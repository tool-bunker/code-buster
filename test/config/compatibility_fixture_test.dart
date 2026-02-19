import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  const String fixture = 'test/fixtures/compatibility/code-buster.toml';

  test('compatibility config fixture freezes documented CLI settings', () {
    final AnalysisConfig config = CodeBusterConfigLoader.loadFromString(
      root: '/project',
      source: File(fixture).readAsStringSync(),
    );

    expect(config.language, 'dart');
    expect(config.languages, orderedEquals(<String>['dart']));
    expect(config.entryPoints, orderedEquals(<String>['lib/main.dart']));
    expect(
      config.ignorePatterns,
      orderedEquals(<String>['generated', 'build']),
    );
    expect(config.minDuplicationLines, 7);
    expect(config.complexityThreshold, 11);
    expect(config.cognitiveThreshold, 16);
    expect(config.maxFileLines, 600);
    expect(config.maxFunctionLines, 120);
    expect(
      config.ruleGroups,
      containsAll(<String>['core', 'dart-style', 'security']),
    );
    expect(config.disabledRules, contains('dart-print'));
    expect(config.severityOverrides['dart-insecure-http'], RuleSeverity.error);
    expect(config.patternRules.single.id, 'no-debug');
    expect(config.structureSourceRoots, orderedEquals(<String>['lib']));
    expect(config.structureMaxTopLevelFiles, 2);
    expect(
      config.structureAllowedTopLevel,
      orderedEquals(<String>['main.dart']),
    );
    expect(config.structureRequiredDirectories, orderedEquals(<String>['src']));
  });

  test('JSON reporting envelope has stable top-level contract', () {
    final String output = FindingReporter().render(
      format: ReportFormat.json,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: const <Finding>[],
      verbose: false,
    );
    final Map<String, dynamic> envelope =
        jsonDecode(output) as Map<String, dynamic>;
    expect(
      envelope.keys,
      orderedEquals(<String>[
        'schemaVersion',
        'version',
        'command',
        'root',
        'files',
        'actionableFindingCount',
        'detailedFindingCount',
        'advisorySummary',
        'findings',
      ]),
    );
    expect(envelope, <String, dynamic>{
      'schemaVersion': reportSchemaVersion,
      'version': 1,
      'command': 'summary',
      'root': '/project',
      'files': 1,
      'findings': <dynamic>[],
      'actionableFindingCount': 0,
      'detailedFindingCount': 0,
      'advisorySummary': <String, dynamic>{
        'total': 0,
        'groups': <String, dynamic>{},
      },
    });
  });

  test('NDJSON reporting emits one stable finding envelope per line', () {
    final String output = FindingReporter().render(
      format: ReportFormat.ndjson,
      command: 'summary',
      root: '/project',
      files: 1,
      findings: const <Finding>[
        Finding(
          code: 'tab-indent',
          severity: RuleSeverity.warn,
          path: 'lib/main.dart',
          line: 2,
          message: 'tab character used for indentation',
        ),
      ],
      verbose: false,
    );
    final List<Map<String, dynamic>> lines = output
        .trim()
        .split('\n')
        .map((String line) => jsonDecode(line) as Map<String, dynamic>)
        .toList(growable: false);
    expect(lines.first['recordType'], 'summary');
    expect(lines.last['schemaVersion'], reportSchemaVersion);
    expect(lines.last['recordType'], 'finding');
    expect(lines.last['code'], 'tab-indent');
    expect(lines.last['path'], 'lib/main.dart');
  });
}
