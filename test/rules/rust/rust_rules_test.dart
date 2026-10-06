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
    static mut CACHE: usize = 0;
    let owner = Box::from_raw(pointer);
    unsafe impl Send for Handle {}
    std::mem::forget(resource);
    dbg!(value);
    todo!("finish this");
    Command::new("sh").arg("-c").arg(input);
    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
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

    expect(
      codes,
      containsAll(<String>{
        'rust-unwrap',
        'rust-expect',
        'rust-panic-macro',
        'rust-undocumented-unsafe-block',
        'rust-static-mut',
        'rust-raw-ownership-reconstruction',
        'rust-manual-send-sync-impl',
        'rust-mem-forget',
        'rust-dbg-macro',
        'rust-todo-macro',
        'rust-command-shell',
        'rust-unbounded-channel',
      }),
    );
  });
  test('ignores cfg-test bodies and explicitly allowed Clippy lints', () {
    const String allowedSource = '''
#![allow(clippy::unwrap_used)]

fn parse() {
    literal.parse().unwrap();
}
''';
    const String mixedSource = '''
fn production() {
    value.expect("required");
}

#[cfg(test)]
if diagnostic_failed {
    response.unwrap();
}

#[cfg(debug_assertions)]
#[allow(clippy::panic)]
{
    panic!("debug invariant");
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[test]
    fn parses_fixture() {
        value.unwrap();
        value.expect("fixture");
        panic!("fixture failure");
    }
}
''';
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{
        'src/allowed.rs': allowedSource,
        'src/mixed.rs': mixedSource,
      },
      language: 'rust',
    );

    final List<Finding> findings = rustRuleRegistry.rules
        .expand((rule) => rule.analyze(context))
        .where(
          (Finding finding) =>
              finding.code == 'rust-unwrap' ||
              finding.code == 'rust-expect' ||
              finding.code == 'rust-panic-macro',
        )
        .toList();

    expect(
      findings.map((Finding finding) => '${finding.code}:${finding.line}'),
      <String>['rust-expect:2'],
    );
  });

  test(
    'reports panic-capable exported FFI and direct async blocking calls',
    () {
      const String source = '''
#[no_mangle]
pub extern "C" fn decode(pointer: *const u8) -> i32 {
    parse(pointer).unwrap()
}

async fn refresh() {
    std::thread::sleep(delay);
    tokio::task::spawn_blocking(|| {
        std::fs::read_to_string(path)
    }).await.unwrap();
}
''';
      final RuleContext context = RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: const <String, String>{'src/lib.rs': source},
        language: 'rust',
      );

      final List<Finding> findings = rustRuleRegistry.rules
          .expand((rule) => rule.analyze(context))
          .where(
            (Finding finding) =>
                finding.code == 'rust-panic-across-ffi-boundary' ||
                finding.code == 'rust-blocking-call-in-async',
          )
          .toList();

      expect(findings.map((Finding finding) => finding.code), <String>[
        'rust-panic-across-ffi-boundary',
        'rust-blocking-call-in-async',
      ]);
    },
  );

  test('accepts documented boundaries and safe shell and async forms', () {
    const String source = r'''
fn boundaries() {
    // SAFETY: pointer is non-null, aligned, initialized, and uniquely owned.
    // The allocation remains live for the duration of this call.
    unsafe { touch_raw(); }
    Command::new("sh").arg("script.sh");
    let sample = r#"static mut FAKE: usize = 0; Command::new(\"sh\").arg(\"-c\")"#;
}

// SAFETY: Handle contains only a thread-safe operating-system token.
unsafe impl Send for Handle {}

#[no_mangle]
pub extern "C" fn guarded() -> i32 {
    std::panic::catch_unwind(|| parse().unwrap()).unwrap_or(-1)
}

async fn refresh() {
    tokio::task::spawn_blocking(|| {
        std::fs::read_to_string(path)
    }).await.unwrap();
}
''';
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{'src/lib.rs': source},
      language: 'rust',
    );

    final Set<String> codes = rustRuleRegistry.rules
        .expand((rule) => rule.analyze(context))
        .map((Finding finding) => finding.code)
        .where(
          (String code) =>
              code == 'rust-undocumented-unsafe-block' ||
              code == 'rust-manual-send-sync-impl' ||
              code == 'rust-command-shell' ||
              code == 'rust-panic-across-ffi-boundary' ||
              code == 'rust-blocking-call-in-async' ||
              code == 'rust-static-mut',
        )
        .toSet();

    expect(codes, isEmpty);
  });
}
