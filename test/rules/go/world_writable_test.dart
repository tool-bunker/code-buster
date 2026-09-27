import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/world_writable.dart';
import 'package:test/test.dart';

void main() {
  test(
    'reports writable file modes but accepts restricted and directory modes',
    () {
      final List<Finding> findings = goWorldWritableRule
          .analyze(
            const RuleContext(
              config: AnalysisConfig(root: '.'),
              sources: <String, String>{
                'main.go': '''
os.Chmod(open, 0o777)
os.WriteFile(path, data, 0666)
os.OpenFile(path, os.O_WRONLY | os.O_CREATE, 0o662)
os.OpenFile(path, os.O_RDONLY, 0o777)
flags := os.O_WRONLY | os.O_CREATE
os.OpenFile(path, flags, 0o666)
os.Chmod(private, 0o600)
os.WriteFile(path, data, 0o644)
os.MkdirAll(path, 0o777)
''',
              },
              language: 'go',
            ),
          )
          .toList();
      expect(findings.map((Finding finding) => finding.line), <int>[
        1,
        2,
        3,
        6,
      ]);
    },
  );
}
