import 'dart:convert';
import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  const String root = 'test/fixtures/mixed_realistic';

  test(
    'mixed-language fixture tracks expected precision and language isolation',
    () {
      final Map<String, Object?> expectations =
          jsonDecode(
                File('$root/precision_expectations.json').readAsStringSync(),
              )
              as Map<String, Object?>;
      final AnalysisRun run = AnalysisRunner().run(
        CodeBusterCliContract.parse(<String>['summary', '--root', root]),
      );
      String signature(String code, String path, int line) =>
          '$code|$path|$line';
      final Set<String> accepted = (expectations['accepted']! as List<Object?>)
          .cast<Map<String, Object?>>()
          .map(
            (Map<String, Object?> item) => signature(
              item['code']! as String,
              item['path']! as String,
              item['line']! as int,
            ),
          )
          .toSet();
      final Set<String> actual = run.findings
          .map((Finding item) => signature(item.code, item.path, item.line))
          .toSet();

      expect(actual, accepted);
      for (final Map<String, Object?> rejected
          in (expectations['rejected']! as List<Object?>)
              .cast<Map<String, Object?>>()) {
        expect(
          run.findings.where(
            (Finding finding) =>
                finding.code == rejected['code'] &&
                finding.path == rejected['path'],
          ),
          isEmpty,
        );
      }
      expect(
        run.languageSummary.keys,
        containsAll(<String>[
          'cpp',
          'dart',
          'typescript',
          'python',
          'sql',
          'wren',
        ]),
      );
      expect(
        run.findings
            .where((Finding item) => item.code == 'duplicate-block')
            .every(
              (Finding item) => item.relatedFiles.every(
                (String related) =>
                    _extension(related) == _extension(item.path),
              ),
            ),
        isTrue,
        reason: 'cross-language duplication must remain isolated',
      );
    },
  );
}

String _extension(String path) => path.substring(path.lastIndexOf('.'));
