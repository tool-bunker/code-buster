import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/generic_rules.dart';
import 'package:code_buster/src/rules/generic/layout_rules.dart';
import 'package:test/test.dart';

void main() {
  test('honors nested Prettier tab indentation policy', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-prettier-',
    );
    addTearDown(() => root.delete(recursive: true));
    Directory('${root.path}/docs').createSync();
    File(
      '${root.path}/docs/.prettierrc',
    ).writeAsStringSync('{"useTabs": true}');

    expect(
      const TabIndentRule().analyze(
        RuleContext(
          config: AnalysisConfig(root: root.path),
          sources: const <String, String>{'docs/style.css': '\t.selector {}'},
          language: 'repository',
        ),
      ),
      isEmpty,
    );
  });

  test('reports source indentation but ignores tabs inside strings', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-tab-content-',
    );
    addTearDown(() => root.delete(recursive: true));
    File('${root.path}/.editorconfig').writeAsStringSync('''
root = true
[*]
indent_style = space
''');

    final List<Finding> findings = const TabIndentRule()
        .analyze(
          RuleContext(
            config: AnalysisConfig(root: root.path),
            sources: const <String, String>{
              'help.lua':
                  'local lines = { [[!_TAG_FILE_ENCODING\\tutf-8\\t//]] }\n'
                  'local text = [[\n'
                  '\tgenerated help\n'
                  ']]\n'
                  '  \tlocal value = 1\n',
              'fixture.ts':
                  'const fixture = `\n'
                  '\tgenerated code\n'
                  '`;\n',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('honors a disabled Biome formatter for line policy', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-biome-',
    );
    addTearDown(() => root.delete(recursive: true));
    File(
      '${root.path}/biome.json',
    ).writeAsStringSync('{"formatter": {"enabled": false}}');

    final Iterable<Finding> findings = const LongLineRule().analyze(
      RuleContext(
        config: AnalysisConfig(root: root.path),
        sources: <String, String>{'src/main.ts': 'x' * 200},
        language: 'repository',
      ),
    );
    expect(findings, isEmpty);
  });

  test('requires formatter evidence before forbidding frontend tabs', () {
    final Iterable<Finding> findings = const TabIndentRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{'src/main.ts': '\tconst value = 1;'},
        language: 'repository',
      ),
    );

    expect(
      findings.where((Finding finding) => finding.code == 'tab-indent'),
      isEmpty,
    );
  });

  test('requires formatter evidence for trailing whitespace', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-editorconfig-trailing-',
    );
    addTearDown(() => root.delete(recursive: true));
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: root.path),
      sources: const <String, String>{'src/main.cs': 'class Main { }  '},
      language: 'repository',
    );

    expect(const TrailingWhitespaceRule().analyze(context), isEmpty);
    File('${root.path}/.editorconfig').writeAsStringSync('''root = true
[*.cs]
trim_trailing_whitespace = true
''');
    expect(
      const TrailingWhitespaceRule()
          .analyze(context)
          .map((Finding finding) => finding.code),
      <String>['trailing-whitespace'],
    );
  });

  test('honors extension-specific EditorConfig tab overrides', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-editorconfig-tabs-',
    );
    addTearDown(() => root.delete(recursive: true));
    File('${root.path}/.editorconfig').writeAsStringSync('''root = true
[*]
indent_style = space
[*.cs]
indent_style = tab
''');

    final Iterable<Finding> findings = const TabIndentRule().analyze(
      RuleContext(
        config: AnalysisConfig(root: root.path),
        sources: const <String, String>{'src/main.cs': '\tvar value = 1;'},
        language: 'repository',
      ),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'tab-indent'),
      isEmpty,
    );
  });

  test('requires formatter evidence for frontend line limits', () async {
    final Directory root = await Directory.systemTemp.createTemp(
      'code-buster-editorconfig-',
    );
    addTearDown(() => root.delete(recursive: true));
    final RuleContext context = RuleContext(
      config: AnalysisConfig(root: root.path),
      sources: <String, String>{'src/main.ts': 'x' * 140},
      language: 'repository',
    );

    expect(const LongLineRule().analyze(context), isEmpty);
    File('${root.path}/.editorconfig').writeAsStringSync('''root = true
[*.ts]
max_line_length = 120
''');
    expect(
      const LongLineRule()
          .analyze(context)
          .map((Finding finding) => finding.code),
      <String>['long-line'],
    );
  });

  test('does not impose Python formatter width without project evidence', () {
    final Iterable<Finding> findings = const LongLineRule().analyze(
      RuleContext(
        config: const AnalysisConfig(root: '.'),
        sources: <String, String>{'tool/main.py': 'value = expression' * 10},
        language: 'repository',
      ),
    );

    expect(findings, isEmpty);
  });

  test(
    'reads JavaScript Prettier printWidth as line-policy evidence',
    () async {
      final Directory root = await Directory.systemTemp.createTemp(
        'code-buster-prettier-width-',
      );
      addTearDown(() => root.delete(recursive: true));
      File(
        '${root.path}/prettier.config.js',
      ).writeAsStringSync('module.exports = { printWidth: 100 };');

      final Iterable<Finding> findings = const LongLineRule().analyze(
        RuleContext(
          config: AnalysisConfig(root: root.path),
          sources: <String, String>{'src/main.js': 'x' * 110},
          language: 'repository',
        ),
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'long-line',
      ]);
    },
  );

  test('reports file limits and goto statements', () {
    final List<Finding> findings = const RepositoryAnalysis().fileFindings(
      sources: <String, String>{'large.c': 'goto done;\nline\nline'},
      config: const AnalysisConfig(root: '.', maxFileLines: 2),
    );
    expect(findings.map((Finding item) => item.code), <String>[
      'large-file',
      'goto-statement',
    ]);
  });

  test('reports language-neutral suspicious constructs', () {
    const Map<String, String> sources = <String, String>{
      'source.dart': '''// TODO: clean up
// FIXME: incorrect
if (value == value) {}
final timeout = 10000000;
final values = [1,2,3,4,5,6,7,8,9,10,11,12,13,14];
''',
    };
    const RuleContext context = RuleContext(
      config: AnalysisConfig(root: '.'),
      sources: sources,
      language: 'repository',
    );
    final Iterable<String> codes =
        const <CodeBusterRule>[
              TodoCommentRule(),
              FixmeCommentRule(),
              OperationOnSameValueRule(),
              LargeNumberUngroupedRule(),
              LargeInlineListRule(),
            ]
            .expand((CodeBusterRule rule) => rule.analyze(context))
            .map((Finding finding) => finding.code);
    expect(
      codes,
      containsAll(<String>[
        'todo-comment',
        'fixme-comment',
        'operation-on-same-value',
        'large-number-ungrouped',
        'large-inline-list',
      ]),
    );
  });

  test('reports todo only from actual comment spans', () {
    final List<Finding> findings = const TodoCommentRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'source.m': '''
// stay tuned for a new easier way todo this coming soon
// Finds and lists all of the TODO, HACK, BUG, etc comments
todos.group(":todoID") { todo in
todo.delete()
context.TODO()
let marker = "TODO // TODO"
// TODO: replace the workaround
// TODO
value(); //todo: remove after migration
/* TODO: remove the compatibility branch */
''',
              'script.py': '''
# todo track the follow-up
label = "TODO # TODO"
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(
      findings.map((Finding finding) => '${finding.path}:${finding.line}'),
      <String>[
        'source.m:7',
        'source.m:8',
        'source.m:9',
        'source.m:10',
        'script.py:1',
      ],
    );
  });

  test('reports fixme only from actual comment spans', () {
    final List<Finding> findings = const FixmeCommentRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'source.go': '''
fixmeHandler()
context.FIXME()
const marker = "FIXME // FIXME"
// Finds and lists all of the FIXME, TODO, BUG, etc comments
// FIXME: replace the workaround
value := 1 /* fixme: remove after migration */
''',
              'script.py': '''
label = "FIXME # FIXME"
# FIXME track the follow-up
# FIXME(owner): track the follow-up
# FIXME
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(
      findings.map((Finding finding) => '${finding.path}:${finding.line}'),
      <String>[
        'source.go:5',
        'source.go:6',
        'script.py:2',
        'script.py:3',
        'script.py:4',
      ],
    );
  });

  test('ignores large numbers in line and block comments', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'source.cpp': '''// https://stackoverflow.com/questions/3279543
/* profiler data:
00.22 0.04 7736490 get_bits
*/
const auto timeout = 10000000; // issue 8111677
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('ignores dependency metadata numbers but checks Dart source', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'core/go.mod': '''
require example.com/module v0.0.0-20250417153138-2c235444b7ba
''',
              'lib/source.dart': 'const timeout = 10000000;',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/source.dart');
  });

  test('ignores large numbers in HTML text and attributes', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'citation.html': '''
<a href="https://doi.org/10.1145/3319535.3363192">
  Published as paper 3319535.
</a>
''',
              'lib/source.dart': 'const timeout = 10000000;',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/source.dart');
  });

  test('ignores URL identifiers and matching commit-hash link labels', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'release.txt': '''
See www.example.test/pull/2485#issuecomment-784355989.
<a href="/livewire/livewire/commit/2495387841a3eb03ac62b2c984ccd2574303285b">2495387</a>
<a href="/livewire/livewire/commit/2495387841a3eb03ac62b2c984ccd2574303285b">7526603</a>
const timeout = 10000000;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3, 4]);
  });

  test('does not require unsupported digit grouping syntax', () {
    final Iterable<Finding> findings = const LargeNumberUngroupedRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{
          'clock.c': 'double seconds = micros / 1000000.0;',
          'theme.css': '.dialog { z-index: 1050000; }',
          'limits.h': '#define MAX_VALUE 2147483647',
          'clock.cpp': 'double seconds = micros / 1000000.0;',
          'clock.m': 'double seconds = micros / 1000000.0;',
        },
        language: 'repository',
      ),
    );

    expect(findings, isEmpty);
  });

  test('accepts floating-point self-comparisons used for NaN checks', () {
    final Iterable<Finding> findings = const OperationOnSameValueRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{
          'number.c': '''
double value = read_number();
if (value != value) return NAN;
if (value == value) return value;
int count = read_count();
if (count == count) return count;
''',
        },
        language: 'repository',
      ),
    );

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('accepts documented generic NaN self-comparisons', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'sort.go': '''
// isNaN reports whether x is a NaN for ordered floating-point values.
func isNaN[T constraints.Ordered](x T) bool {
  return x != x
}
func same[T comparable](x T) bool {
  return x == x
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 6);
  });

  test('accepts a self-comparison with a following explicit NaN guard', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'typecheck.luau': '''
function t.number(value)
  if typeof(value) == "number" then
    if value == value then
      return true
    else
      return false, "unexpected NaN value"
    end
  end
end
if count == count then return count end
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 10);
  });

  test('accepts paired self-comparisons used for JavaScript NaN handling', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'equality.js': '''
return a != a
  ? b == b
  : a !== b;
const mistakenEqual = left == left;
const mistakenUnequal = right != right;
return value != value
  ? value == value
  : false;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5, 6, 7]);
  });

  test('honors adjacent no-self-compare directives only', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'same_value.js': '''
const value = readValue();
// eslint-disable-next-line no-self-compare
if (value != value) return true;
if (other != other) return true;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('ignores CSS selectors that repeat the same element name', () {
    final Iterable<Finding> findings = const OperationOnSameValueRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{
          'styles.css': '.map-accordion div > div:last-child { margin: 0; }',
        },
        language: 'repository',
      ),
    );

    expect(findings, isEmpty);
  });

  test('ignores same-value comparisons inside explicit assertions', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'comparison_test.cpp': '''
CPPUNIT_ASSERT(!(iterator <= iterator));
assert(value == value);
EXPECT_TRUE(check(iterator >= iterator));
if (value == value) {}
assert(isReady()); if (other >= other) {}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5]);
  });

  test('ignores member access using a macro parameter as the property', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'paragraph.m': '''
#define SetProperty(_property_) \\
if (value. _property_ == _property_) return
SetProperty(alignment);
if (value == value) return;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('does not erase meaningful casts from comparison operands', () {
    final List<Finding> findings = const OperationOnSameValueRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'bounds.c': '''
if ((size_t)allocationSize != allocationSize) return false;
if ((float)(int)value == value) return true;
if (value == value) return false;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });

  test('keeps boolean-return branches within one control-flow sequence', () {
    final List<Finding> findings = const NeedlessBoolBranchRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(
              root: '.',
              ruleGroups: <String>{'suspicious'},
            ),
            sources: <String, String>{
              'vector.hpp': '''
inline bool contains(const T& value) { while (item != end) if (*item++ == value) return true; return false; }
inline T* find(const T& value) { return data; }
inline bool erase(const T& value) { if (value) return true; return false; }
// if (example) return true;
// return false;
bool direct(bool ready) {
  if (ready) return true;
  return false;
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 7);
  });

  test('reports a direct boolean if/else decision', () {
    final List<Finding> findings = const NeedlessBoolBranchRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(
              root: '.',
              ruleGroups: <String>{'suspicious'},
            ),
            sources: <String, String>{
              'predicate.cpp': '''
bool isReady(bool ready) {
  if (ready) return true;
  else return false;
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 2);
  });

  test('distinguishes string coercion from a direct boolean decision', () {
    final List<Finding> findings = const NeedlessBoolBranchRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(
              root: '.',
              ruleGroups: <String>{'suspicious'},
            ),
            sources: <String, String>{
              'coerce.ts': '''
function coerceValue(value: string): boolean | string {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}

function isReady(ready: boolean): boolean {
  if (ready) return true;
  return false;
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 8);
  });

  test('preserves side effects between boolean returns', () {
    final List<Finding> findings = const NeedlessBoolBranchRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(
              root: '.',
              ruleGroups: <String>{'suspicious'},
            ),
            sources: <String, String>{
              'limiter.cpp': '''
bool Acquire(int previous) {
  if (previous > 0) return true;
  restoreCapacity();
  return false;
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('does not cross an enclosing scope for a later false return', () {
    final Iterable<Finding> findings = const NeedlessBoolBranchRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.', ruleGroups: <String>{'suspicious'}),
        sources: <String, String>{
          'search.ts': '''
function anyStrong(terms: string[]): boolean {
  for (const term of terms) {
    if (term.length > 2) return true;
  }
  return false;
}
''',
        },
        language: 'repository',
      ),
    );

    expect(findings, isEmpty);
  });

  test('does not pair a polling-loop success with its timeout return', () {
    final Iterable<Finding> findings = const NeedlessBoolBranchRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.', ruleGroups: <String>{'suspicious'}),
        sources: <String, String>{
          'process.cpp': '''
bool waitForRunning() {
  while (beforeTimeout()) {
    if (isRunning()) return true;
    sleep();
  }
  return false;
}
''',
        },
        language: 'repository',
      ),
    );

    expect(findings, isEmpty);
  });

  test('ignores large inline collections in comments', () {
    final List<Finding> findings = const LargeInlineListRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'kernel.cpp': '''
// shift = [0, 8, 16, 24, 2, 10, 18, 26, 4, 12, 20, 28, 6, 14, 22, 30]
/* index = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15} */
const values = [0, 8, 16, 24, 2, 10, 18, 26, 4, 12, 20, 28, 6, 14];
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });

  test('ignores large inline collections in cfg-test Rust modules', () {
    final List<Finding> findings = const LargeInlineListRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'src/lib.rs': '''
#[cfg(test)]
mod tests {
    fn parses_address() {
        let address = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    }
}
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('ignores inline data tables in generated source', () {
    final List<Finding> findings = const LargeInlineListRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'tables.go': '''
// Code generated by running "go generate". DO NOT EDIT.
var offsets = []uint16{0x0, 0x9, 0xf, 0x18, 0x24, 0x2e, 0x34, 0x37, 0x3b, 0x3e, 0x42, 0x4c, 0x4e}
''',
              'values.go':
                  'var values = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'values.go');
  });

  test('distinguishes command arguments from prepared argument lists', () {
    final List<Finding> findings = const SuspiciousCommandArgumentRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'setup.py': '''
subprocess.run(["cmake", "--version"], capture_output=True)
subprocess.run(["cmake", "--build", "build"])
subprocess.run("sysctl -n sysctl.proc_translated".split(), capture_output=True)
subprocess.run(["cmake --version"])
subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('ignores comments and split command tokens', () {
    final List<Finding> findings = const SuspiciousCommandArgumentRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'tool.dart': '''
Process.run('uname', ['-m']);
// Process.run('commented unsafe command', []);
/*
Process.start('also commented unsafe command', []);
*/
final cmd = 'flutter build macos';
Process.start(cmd.split(' ')[0], cmd.split(' ').sublist(1));
Process.start('unsafe command', []);
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 8);
  });
}
