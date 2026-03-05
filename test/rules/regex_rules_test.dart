import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/regex/regex_rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports invalid, unsafe, misleading, and repeated regex patterns', () {
    final Iterable<String> codes = RegexRuleAnalysis()
        .findings(<String, String>{
          'patterns.dart': r'''
final invalid = RegExp(r'[');
final literal = RegExp('x');
final first = RegExp('[A-z]+');
final second = RegExp('[A-z]+');
if (RegExp('ordinary').hasMatch(input)) {}
final RegExpMatch? ordinaryMatch = RegExp('ordinary').firstMatch(input);
final validationEmail = RegExp('.*(a+)+|');
''',
        })
        .map((Finding item) => item.code);

    expect(
      codes,
      containsAll(<String>[
        'regex-invalid',
        'regex-single-literal',
        'regex-a-z-range',
        'regex-repeated-compile',
        'regex-unanchored-validation',
        'regex-catastrophic-backtracking-risk',
        'regex-leading-dot-star',
        'regex-empty-alternative',
      ]),
    );
    expect(
      codes.where((String code) => code == 'regex-unanchored-validation'),
      hasLength(1),
    );
  });

  test('distinguishes escaped literal pipes from empty alternatives', () {
    final List<Finding> findings = RegexRuleAnalysis()
        .findings(<String, String>{
          'patterns.js': r'''
const tableLabel = line.match(/^\|\s*\*\*(.+?)\*\*\s*\|/);
const shellSyntax = /\bcommand\s+-v\b|&&|\|\||>\/dev\/null|2>&1/;
const classPipe = /[|]/;
const leadingEmpty = /|value/;
const trailingEmpty = /value|/;
const adjacentEmpty = /value||other/;
''',
        })
        .where((Finding finding) => finding.code == 'regex-empty-alternative')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5, 6]);
  });

  test(
    'does not validate interpolated Dart regular expressions as literals',
    () {
      final List<Finding> findings = RegexRuleAnalysis()
          .findings(<String, String>{
            'dynamic.dart':
                r"final pattern = RegExp('\\b${RegExp.escape(name)}\\(');",
          });

      expect(
        findings.where((Finding finding) => finding.code == 'regex-invalid'),
        isEmpty,
      );
    },
  );

  test('respects Dart string semantics and bounded optional groups', () {
    final List<Finding> findings = RegexRuleAnalysis()
        .findings(const <String, String>{
          'patterns.dart': r'''
final anchor = RegExp('^\\s*name\\s*\\$');
final dynamic = RegExp('^$typeName\\(');
final bounded = RegExp(r'^(\d+){0,1}$');
final bracketGuard = RegExp(r'(\(.*?\)+)|(\[.*?\]+)');
''',
        });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'regex-invalid' ||
            finding.code == 'regex-catastrophic-backtracking-risk',
      ),
      isEmpty,
    );
  });

  test('accepts search assertions and separator-delimited repetition', () {
    final Iterable<Finding> findings = RegexRuleAnalysis()
        .findings(<String, String>{
          'sample.js': r'''
expect(validateProjectPath('/etc')).toMatch(/sensitive system directory/i);
const path = /(?:[\w@.+-]+\/)+[\w@.+-]+\.[A-Za-z]\w*/g;
''',
        })
        .where(
          (Finding finding) =>
              finding.code == 'regex-unanchored-validation' ||
              finding.code == 'regex-catastrophic-backtracking-risk',
        );

    expect(findings, isEmpty);
  });

  test('requires actual validation use for unanchored expressions', () {
    final List<Finding> findings = RegexRuleAnalysis()
        .findings(<String, String>{
          'lookup.js': r'''
const metadata = [
  [/validates email/, 'email-validation', 'Email Validation'],
];
const picked = rows.find((row) => /validates email/.test(row.label));
const isValidEmail = (value) => /.+@.+/.test(value);
const validatorPattern = /[a-z]+/;
''',
        })
        .where(
          (Finding finding) => finding.code == 'regex-unanchored-validation',
        )
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5, 6]);
  });

  test('only parses slash literals in JavaScript and ignores quoted paths', () {
    final List<Finding>
    findings = RegexRuleAnalysis().findings(<String, String>{
      'sample.dart':
          "import 'src/one.dart';\nfinal ratio = total / count;\n// RegExp('[A-z]+')",
      'sample.js': '''
const path = "essentials/provider/network";
/* POST /api/invalidate-cache
 * fake /[/ and RegExp('[')
 */
const ratio = total / count;
const pattern = /[A-z]+/;
const repeated = /[A-z]+/;
// const fake = /[/;
''',
    });

    expect(
      findings.where((Finding finding) => finding.path == 'sample.dart'),
      isEmpty,
    );
    expect(
      findings.where((Finding finding) => finding.code == 'regex-a-z-range'),
      hasLength(2),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'regex-invalid'),
      isEmpty,
    );
    expect(
      findings.where(
        (Finding finding) => finding.code == 'regex-repeated-compile',
      ),
      isEmpty,
    );
    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'regex-unanchored-validation' &&
            finding.path == 'sample.dart',
      ),
      isEmpty,
    );
  });
}
