import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/world_writable.dart';
import 'package:test/test.dart';

void main() {
  test('reports world-writable chmod but accepts restricted modes', () {
    final List<Finding> findings = goWorldWritableRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'main.go': 'os.Chmod(open, 0777)\nos.Chmod(private, 0600)',
            },
            language: 'go',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });
}
