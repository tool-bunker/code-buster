import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('imports attributed SARIF findings and rejects escaping paths', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-sarif-');
    addTearDown(() => root.deleteSync(recursive: true));
    final File report = File('${root.path}/external.sarif')
      ..writeAsStringSync(
        jsonEncode(<String, Object>{
          'runs': <Object>[
            <String, Object>{
              'tool': <String, Object>{
                'driver': <String, Object>{'name': 'Other Scanner'},
              },
              'results': <Object>[
                <String, Object>{
                  'ruleId': 'unsafe-call',
                  'level': 'warning',
                  'message': <String, Object>{'text': 'Review this call'},
                  'locations': <Object>[
                    <String, Object>{
                      'physicalLocation': <String, Object>{
                        'artifactLocation': <String, Object>{
                          'uri': 'lib/main.dart',
                        },
                        'region': <String, Object>{'startLine': 4},
                      },
                    },
                  ],
                },
                <String, Object>{
                  'ruleId': 'escape',
                  'locations': <Object>[
                    <String, Object>{
                      'physicalLocation': <String, Object>{
                        'artifactLocation': <String, Object>{
                          'uri': '../outside.dart',
                        },
                      },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      );

    final SarifIngestionResult result = const SarifIngestion().read(<String>[
      report.path,
    ], root.path);
    expect(result.diagnostics, isEmpty);
    expect(result.findings, hasLength(1));
    expect(result.findings.single.code, 'external:other-scanner:unsafe-call');
    expect(result.findings.single.path, 'lib/main.dart');
    expect(result.findings.single.confidence, 'external');
  });

  test('reports malformed input as processing diagnostics', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-sarif-');
    addTearDown(() => root.deleteSync(recursive: true));
    final File report = File('${root.path}/broken.sarif')
      ..writeAsStringSync('{');

    final SarifIngestionResult result = const SarifIngestion().read(<String>[
      report.path,
    ], root.path);
    expect(result.findings, isEmpty);
    expect(result.diagnostics.single.code, 'sarif-ingestion-failed');
  });
}
