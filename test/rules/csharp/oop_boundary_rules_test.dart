import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/csharp/oop_boundary_rules.dart';
import 'package:code_buster/src/rules/csharp/oop_rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports dominant factory bypass', () {
    final findings = _findings({
      'Factory.cs': 'class WidgetFactory { Widget Make() => new Widget(); }',
      'A.cs': 'class A { WidgetFactory factory; }',
      'B.cs': 'class B { WidgetFactory factory; }',
      'C.cs': 'class C { WidgetFactory factory; }',
      'Bypass.cs': 'class Bypass { Widget Make() => new Widget(); }',
    });
    expect(findings.map((f) => f.code), contains('oop-factory-bypass'));
  });

  test('reports facade repository and proxy bypasses', () {
    final findings = _findings({
      'Boundaries.cs': '''
class OrderFacade { private OrderService orders; private PaymentGateway payments; private MailClient mail; }
class OrderRepository { private OrderDatabase database; }
class OrderProxy { private OrderService service; }
''',
      'A.cs':
          'class A { OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'B.cs':
          'class B { OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'C.cs':
          'class C { OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'Bypass.cs':
          'class Bypass { OrderService orders; PaymentGateway payments; OrderDatabase database; }',
    });
    expect(
      findings.map((f) => f.code),
      containsAll([
        'oop-facade-bypass',
        'oop-repository-bypass',
        'oop-proxy-bypass',
      ]),
    );
  });

  test('reports repeated mapping and sibling workflow', () {
    final findings = _findings({
      'A.cs':
          'class A { Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City }; } class One : Base { public override void Run() { Open(); Read(); OneStep(); Close(); } }',
      'B.cs':
          'class B { Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City }; } class Two : Base { public override void Run() { Open(); Read(); TwoStep(); Close(); } }',
      'C.cs':
          'class C { Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City }; }',
    });
    expect(
      findings.map((f) => f.code),
      containsAll([
        'oop-repeated-adapter-mapping',
        'oop-template-workflow-candidate',
      ]),
    );
  });

  test('ignores comments, strings, weak boundaries, and partial mappings', () {
    final findings = _findings({
      'Safe.cs': '''
class WidgetFactory { Widget Make() => new Widget(); }
class A { WidgetFactory factory; }
class Safe { string Text() => "new Widget()"; Target Map(Source s) => new Target { Name = s.Name, Age = s.Age }; }
// class Fake { Widget Make() => new Widget(); }
''',
    });
    expect(findings.where((f) => ids.contains(f.code)), isEmpty);
  });
}

List<Finding> _findings(Map<String, String> sources) {
  final project = CSharpOopProject.parse(sources);
  final context = RuleContext(
    config: const AnalysisConfig(root: '.'),
    sources: sources,
    language: 'csharp',
    languageAnalysis: project,
  );
  return [for (final id in ids) ...CSharpOopRule(id).analyze(context)];
}
