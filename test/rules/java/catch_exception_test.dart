import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/catch_exception.dart';
import 'package:test/test.dart';

void main() {
  test('reports broad handlers but accepts specific exceptions', () {
    final List<Finding> findings = javaCatchExceptionRule
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'Main.java':
                  '''try { run(); } catch (Exception error) { recover(); }
try { run(); } catch (IOException error) { recover(); }
''',
            },
            language: 'java',
          ),
        )
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });
}
