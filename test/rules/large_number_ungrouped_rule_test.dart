import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/generic/generic_rules.dart';
import 'package:test/test.dart';

void main() {
  test('does not recommend unavailable digit grouping in C-family sources', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'native/client.c': 'const long timeout = 10000000;',
              'native/client.h': '#define TIMEOUT 10000000',
              'objc/Plugin.m': 'const long timeout = 10000000;',
              'cpp/client.cpp': 'const long timeout = 10000000;',
              'cpp/client.hpp': 'constexpr long timeout = 10000000;',
              'java/Server.java': 'long timeout = 10000000L;',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.path), <String>[
      'cpp/client.cpp',
      'cpp/client.hpp',
      'java/Server.java',
    ]);
  });

  test('does not recommend digit grouping that standard Lua cannot parse', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'plugin/config.lua': 'local context_window = 1048576',
              'server/Config.java': 'long contextWindow = 1048576;',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.path), <String>[
      'server/Config.java',
    ]);
  });

  test('does not treat fractional digits as a large integer', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'script.lua': '''
local ratio = 0.551915024494
local count = 551915024494
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, isEmpty);
  });

  test('ignores legacy octal integers without hiding decimal values', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'permissions.cpp': '''
constexpr auto owner = 0000700;
constexpr auto group = 0000070;
constexpr auto other = 0000007;
constexpr auto decimal = 10000000;
constexpr auto invalidOctalEight = 0000008;
constexpr auto invalidOctalNine = 0000009;
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5, 6]);
  });

  test('ignores numeric examples in Python docstrings', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'stats.py': '''
"""
Example timestamp:
    10474959 start flip
"""
timeout = 10474959
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('ignores literals in definitely disabled preprocessor branches', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'benchmark.cpp': '''#if 0
const long disabled = 10000000;
#else
const long active = 20000000;
#endif
''',
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('ignores numbers inside Dart raw multiline strings', () {
    final List<Finding> findings = const LargeNumberUngroupedRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'embedded.dart': r"""const script = r'''
const timestamp = 10474959;
''';
const actual = 20474959;
""",
            },
            language: 'repository',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });
}
