import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/empty_catch.dart';
import 'package:test/test.dart';

void main() {
  test('reports empty and comment-only catches but not handled catches', () {
    const String source = '''
class Loader {
  void load() {
    try {
      first();
    } catch (IOException error) {
    }
    try {
      second();
    } catch (IOException error) {
      // Intentionally ignored.
    }
    try {
      third();
    } catch (IOException error) {
      throw new IllegalStateException(error);
    }
  }
}
''';

    final List<Finding> findings = const JavaEmptyCatchRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: const <String, String>{'Loader.java': source},
            language: 'java',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5, 9]);
  });
}
