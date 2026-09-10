import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/odin/rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports Odin failure and memory-safety boundaries', () {
    const String source = '''package main

run :: proc() {
    panic("failed")
    bits := transmute(u32)f32_value
    pointer: rawptr = raw_data(value)
    bytes: [16]u8 = ---
}
''';
    final RuleContext context = RuleContext(
      config: const AnalysisConfig(root: '.'),
      sources: const <String, String>{'main.odin': source},
      language: 'odin',
    );

    final List<Finding> findings = odinRuleRegistry.rules
        .expand((CodeBusterRule rule) => rule.analyze(context))
        .toList();

    expect(findings.map((Finding finding) => finding.code), <String>[
      'odin-panic-call',
      'odin-transmute',
      'odin-raw-pointer',
      'odin-undefined-value',
    ]);
    expect(findings.map((Finding finding) => finding.line), <int>[4, 5, 6, 7]);
  });

  test('ignores Odin-looking text in nested comments and literals', () {
    const String source = '''package main

run :: proc() {
    // panic("example")
    text := "transmute(rawptr)"
    raw := `value = ---`
    /* rawptr
       /* panic("nested") */
       transmute(u32)value
    */
}
''';
    final RuleContext context = RuleContext(
      config: const AnalysisConfig(root: '.'),
      sources: const <String, String>{'main.odin': source},
      language: 'odin',
    );

    expect(
      odinRuleRegistry.rules.expand(
        (CodeBusterRule rule) => rule.analyze(context),
      ),
      isEmpty,
    );
  });
}
