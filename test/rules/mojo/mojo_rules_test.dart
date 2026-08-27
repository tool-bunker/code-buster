import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/mojo/rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports removed Mojo syntax and missing raises declarations', () {
    const String source = '''
from pathlib import Path

alias Size = Int

@parameter
fn legacy(inout value: Int):
    let text = "hello"
    print(text[0])

def fail():
    raise Error("failed")

# let ignored = 1
var example = "fn ignored()"
var docs = """
fn documented():
    let text = name[0]
"""
''';
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{'main.mojo': source},
      language: 'mojo',
    );

    final Set<String> codes = mojoRuleRegistry.rules
        .expand((rule) => rule.analyze(context))
        .map((finding) => finding.code)
        .toSet();

    expect(codes, <String>{
      'mojo-deprecated-fn',
      'mojo-deprecated-let',
      'mojo-deprecated-alias',
      'mojo-parameter-decorator',
      'mojo-legacy-argument-convention',
      'mojo-legacy-stdlib-import',
      'mojo-string-index',
      'mojo-missing-raises',
    });
  });
}
