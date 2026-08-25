import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/ui/ui_consistency.dart';
import 'package:test/test.dart';

void main() {
  group('UI consistency rules', () {
    test('reports duplicate CSS declaration sets across selectors', () {
      final List<Finding> findings = const CssDuplicateDeclarationSetRule()
          .analyze(
            _context(<String, String>{
              'primary.css': '''
.primary {
  color: #fff;
  background: #369;
  padding: 12px 24px;
  border-radius: 6px;
}
''',
              'confirm.css': '''
.confirm {
  border-radius: 6px;
  padding: 12px 24px;
  background: #369;
  color: #ffffff;
}
''',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'css-duplicate-declaration-set');
      expect(findings.single.relatedFiles, <String>['primary.css:1']);
    });

    test('reports raw CSS values matching an existing token', () {
      final List<Finding> findings = const CssDesignTokenDriftRule()
          .analyze(
            _context(<String, String>{
              'tokens.css': ':root { --color-primary: #336699; }',
              'card.css': '.card { color: #369; }',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'css-design-token-drift');
      expect(findings.single.message, contains('--color-primary'));
    });

    test('reports repeated substantial Flutter inline styles', () {
      const String style = '''TextStyle(
  color: Colors.white,
  fontSize: 16,
  fontWeight: FontWeight.w600,
)''';
      final List<Finding> findings = const FlutterRepeatedInlineStyleRule()
          .analyze(
            _context(<String, String>{
              'lib/save.dart': 'final saveStyle = $style;',
              'lib/confirm.dart': 'final confirmStyle = $style;',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'flutter-repeated-inline-style');
      expect(findings.single.relatedFiles, <String>['lib/save.dart:1']);
    });

    test('reports Flutter color values bypassing a project token', () {
      final List<Finding> findings = const FlutterThemeBypassRule()
          .analyze(
            _context(<String, String>{
              'lib/theme.dart':
                  'abstract final class AppColors { static const primary = Color(0xff336699); }',
              'lib/button.dart':
                  'final button = Container(color: const Color(0xff336699));',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'flutter-theme-bypass');
      expect(findings.single.message, contains('primary'));
    });

    test('reports button-like Flutter pointer trees beside buttons', () {
      final List<Finding> findings = const FlutterParallelControlComponentRule()
          .analyze(
            _context(<String, String>{
              'lib/save.dart':
                  "final save = ElevatedButton(onPressed: save, child: Text('Save'));",
              'lib/confirm.dart': '''
final confirm = GestureDetector(
  onTap: confirmAction,
  child: Container(child: Text('Confirm')),
);
''',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'flutter-parallel-control-component');
      expect(findings.single.relatedFiles, <String>['lib/save.dart:1']);
    });

    test('reports direct controls bypassing an established shared widget', () {
      final List<Finding> findings = const FlutterSharedComponentBypassRule()
          .analyze(
            _context(<String, String>{
              'lib/app_button.dart': '''
class AppButton extends StatelessWidget {
  Widget build(BuildContext context) {
    return ElevatedButton(onPressed: save, child: Text('Save'));
  }
}
''',
              'lib/profile.dart':
                  'final a = AppButton(); final b = AppButton();',
              'lib/checkout.dart': 'final c = AppButton();',
              'lib/settings.dart':
                  "final submit = ElevatedButton(onPressed: save, child: Text('Submit'));",
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'flutter-shared-component-bypass');
      expect(findings.single.path, 'lib/settings.dart');
      expect(findings.single.message, contains('AppButton'));
      expect(findings.single.message, contains('used 3 times'));
      expect(findings.single.relatedFiles.first, 'lib/app_button.dart:1');
    });

    test('reports button-like HTML elements beside native buttons', () {
      final List<Finding> findings = const HtmlParallelControlPatternRule()
          .analyze(
            _context(<String, String>{
              'save.html': '<button type="button">Save</button>',
              'confirm.html': '<a href="#" role="button">Confirm</a>',
            }),
          )
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.code, 'html-parallel-control-pattern');
      expect(findings.single.relatedFiles, <String>['save.html:1']);
    });
  });
}

RuleContext _context(Map<String, String> sources) => RuleContext(
  config: AnalysisConfig(root: '.'),
  sources: sources,
  language: 'repository',
);
