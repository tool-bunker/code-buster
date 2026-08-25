import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/java/string_concat_loop.dart';
import 'package:test/test.dart';

void main() {
  test('reports String accumulation in loops only', () {
    const String source = '''
class Formatter {
  String format(List<String> values) {
    String result = "";
    int total = 0;
    result += "prefix";
    for (String value : values) {
      result += value;
      total += value.length();
    }
    while (total > 10) {
      result = result + "!";
      total--;
    }
    return result;
  }
}
''';

    final List<Finding> findings = const JavaStringConcatLoopRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: const <String, String>{'Formatter.java': source},
            language: 'java',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[7, 11]);
  });
}
