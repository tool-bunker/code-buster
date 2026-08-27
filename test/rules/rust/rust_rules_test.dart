import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/rust/rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports production Rust failure, safety, and debug risks', () {
    const String source = '''
use std::process::Command;

fn run() {
    value.unwrap();
    value.expect("required");
    panic!("failed");
    unsafe { touch_raw(); }
    std::mem::forget(resource);
    dbg!(value);
    todo!("finish this");
    Command::new("sh").arg("-c").arg(input);
    // panic!("comment");
    let example = "value.unwrap()";
}
''';
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{'src/main.rs': source},
      language: 'rust',
    );

    final Set<String> codes = rustRuleRegistry.rules
        .expand((rule) => rule.analyze(context))
        .map((finding) => finding.code)
        .toSet();

    expect(codes, <String>{
      'rust-unwrap',
      'rust-expect',
      'rust-panic-macro',
      'rust-unsafe-block',
      'rust-mem-forget',
      'rust-dbg-macro',
      'rust-todo-macro',
      'rust-command-shell',
    });
  });
}
