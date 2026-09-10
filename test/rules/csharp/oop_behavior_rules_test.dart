import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/csharp/oop_behavior_rules.dart';
import 'package:code_buster/src/rules/csharp/oop_rules.dart';
import 'package:test/test.dart';

void main() {
  test('reports repeated strategy dispatch across files', () {
    final findings = _findings({
      'A.cs':
          'class A { void Run(Kind k) { switch(k) { case Kind.A: A1(); break; case Kind.B: B1(); break; case Kind.C: C1(); break; } } }',
      'B.cs':
          'class B { void Run(Kind k) { switch(k) { case Kind.A: A2(); break; case Kind.B: B2(); break; case Kind.C: C2(); break; } } }',
      'C.cs':
          'class C { void Run(Kind k) { switch(k) { case Kind.A: A3(); break; case Kind.B: B3(); break; case Kind.C: C3(); break; } } }',
    });
    expect(
      findings.map((finding) => finding.code),
      contains('oop-repeated-strategy-dispatch'),
    );
  });

  test('reports repeated behavior over one state field', () {
    final findings = _findings({
      'State.cs': '''
class Machine {
  private Status _status;
  void A() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
  void B() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
  void C() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
}
''',
    });
    expect(
      findings.map((finding) => finding.code),
      contains('oop-state-behavior-candidate'),
    );
  });

  test('reports feature envy and distributed service lookup', () {
    final findings = _findings({
      'A.cs': '''
class A {
  void Use(Customer c) { c.Name(); c.Name(); c.Address(); c.Address(); c.Credit(); }
  void Locate() { Services.Resolve<Mail>(); }
}
''',
      'B.cs': '''
class B {
  void Locate() { Services.Resolve<Clock>(); }
}
''',
      'C.cs': '''
class C {
  void Locate() { Services.Resolve<Store>(); }
}
''',
    });
    expect(
      findings.map((finding) => finding.code),
      containsAll(['oop-feature-envy', 'oop-service-locator-dependency']),
    );
  });

  test('reports repeated observer loops and message chains', () {
    final findings = _findings({
      'Collaboration.cs': '''
class Subject {
  private List<Listener> listeners;
  void Add(Listener listener) { listeners.Add(listener); }
  void Remove(Listener listener) { listeners.Remove(listener); }
  void A() { foreach (var listener in listeners) listener.Changed(); var x = root.A.B.C.D; }
  void B() { foreach (var listener in listeners) listener.Changed(); var x = root.A.B.C.D; var y = root.E.F.G.H; }
  void C() { foreach (var listener in listeners) listener.Changed(); }
}
''',
    });
    expect(
      findings.map((finding) => finding.code),
      containsAll(['oop-repeated-observer-notification', 'oop-message-chain']),
    );
  });

  test('ignores comments, strings, and evidence below thresholds', () {
    final findings = _findings({
      'Safe.cs': '''
class Safe {
  private List<Listener> listeners;
  void Add(Listener listener) { listeners.Add(listener); }
  void One(Customer c) { c.Name(); c.Address(); var text = "root.A.B.C.D"; }
  // void Fake() { foreach (var listener in listeners) listener.Changed(); }
  string Raw() => """switch(x) { case A: Go(); case B: Go(); case C: Go(); }""";
}
''',
    });
    expect(
      findings.where(
        (finding) => csharpOopBehaviorRuleIds.contains(finding.code),
      ),
      isEmpty,
    );
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
  return [
    for (final id in csharpOopBehaviorRuleIds)
      ...CSharpOopRule(id).analyze(context),
  ];
}
