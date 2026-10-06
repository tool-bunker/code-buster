import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/rust/cargo_rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports Git dependencies without immutable revisions', () {
    const String manifest = '''
[dependencies]
movable = { git = "https://example.com/movable.git", branch = "main" }
pinned = { git = "https://example.com/pinned.git", rev = "0123456789abcdef" }
registry = "1.2.3"

[build-dependencies]
build-helper = { git = "https://example.com/build.git", tag = "v1" }

[target.'cfg(unix)'.dependencies]
target-helper = { git = "https://example.com/target.git" }
''';
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{},
      language: 'rust',
      auxiliaryFiles: const <String, String>{'Cargo.toml': manifest},
    );

    final List<Finding> findings = RustUnpinnedGitDependencyRule()
        .analyze(context)
        .toList();

    expect(
      findings.map((Finding finding) => '${finding.message}:${finding.line}'),
      <String>[
        'Git dependency movable is not pinned with an immutable rev:2',
        'Git dependency build-helper is not pinned with an immutable rev:7',
        'Git dependency target-helper is not pinned with an immutable rev:10',
      ],
    );
  });

  test('ignores malformed manifests and non-Git workspace inheritance', () {
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: const <String, String>{},
      language: 'rust',
      auxiliaryFiles: const <String, String>{
        'member/Cargo.toml': '''
[dependencies]
shared = { workspace = true }
local = { path = "../local" }
''',
        'broken/Cargo.toml': '[dependencies',
      },
    );

    expect(RustUnpinnedGitDependencyRule().analyze(context), isEmpty);
  });
}
