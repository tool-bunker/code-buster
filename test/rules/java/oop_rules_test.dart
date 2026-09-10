import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('reports repeated Java parameter concepts', () {
    final analysis = _analyze({
      'A.java':
          'class A { void run(String tenant, int region, boolean active) {} }',
      'B.java':
          'class B { void save(String tenant, int region, boolean active) {} }',
      'C.java':
          'class C { void send(String tenant, int region, boolean active) {} }',
    });
    expect(analysis.findings.map((f) => f.code), contains('oop-data-clump'));
  });

  test('reports a Java forwarding middle man', () {
    final analysis = _analyze({
      'Gateway.java': '''
class Gateway {
  private Client client;
  public Result load(Id id) { return client.load(id); }
  public Result save(Id id) { return client.save(id); }
  public Result delete(Id id) { return client.delete(id); }
  public Result refresh(Id id) { return client.refresh(id); }
  public Result inspect(Id id) { return client.inspect(id); }
}
''',
    });
    expect(
      analysis.findings.map((f) => f.code),
      contains('oop-middle-man-delegation'),
    );
  });

  test('reports Java contract and inheritance rejection pressure', () {
    final analysis = _analyze({
      'Channel.java': '''
interface ChannelContract {
  void open();
  void close();
  void send();
  void receive();
}
class Channel {
  public void open() {}
  public void close() {}
  public void send() {}
  public void receive() {}
}
''',
      'Input.java': '''
class Input extends Channel implements ChannelContract {
  @Override
  public void send() { throw new UnsupportedOperationException(); }
  @Override
  public void close() { throw new UnsupportedOperationException(); }
}
''',
      'Output.java': '''
class Output extends Channel implements ChannelContract {
  @Override
  public void receive() { throw new UnsupportedOperationException(); }
  @Override
  public void open() { throw new UnsupportedOperationException(); }
}
''',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll([
        'oop-interface-segregation-pressure',
        'oop-refused-bequest',
      ]),
    );
  });

  test('reports Java strategy dispatch and state behavior', () {
    final analysis = _analyze({
      'A.java': '''
class A {
  private Status status;
  void one(Kind kind) { switch(kind) { case A: a(); case B: b(); case C: c(); } switch(status) { case A: a(); case B: b(); case C: c(); } }
  void two() { switch(status) { case A: a(); case B: b(); case C: c(); } }
  void three() { switch(status) { case A: a(); case B: b(); case C: c(); } }
}
''',
      'B.java':
          'class B { void run(Kind kind) { switch(kind) { case A: a(); case B: b(); case C: c(); } } }',
      'C.java':
          'class C { void run(Kind kind) { switch(kind) { case A: a(); case B: b(); case C: c(); } } }',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll([
        'oop-repeated-strategy-dispatch',
        'oop-state-behavior-candidate',
      ]),
    );
  });

  test('reports Java feature envy and repeated message chains', () {
    final analysis = _analyze({
      'Service.java': '''
class Service {
  void inspect(Customer customer) { customer.name(); customer.name(); customer.address(); customer.address(); customer.credit(); }
  void first() { root.account().profile().address().city(); root.account().profile().contact().email(); }
  void second() { root.order().customer().address().city(); }
}
''',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll(['oop-feature-envy', 'oop-message-chain']),
    );
  });

  test('reports Java service location and observer broadcasts', () {
    final analysis = _analyze({
      'Subject.java': '''
class Subject {
  private List<Listener> listeners;
  void add(Listener listener) { listeners.add(listener); }
  void remove(Listener listener) { listeners.remove(listener); }
  void first() { for (Listener listener : listeners) listener.changed(); }
  void second() { for (Listener listener : listeners) listener.changed(); }
  void third() { for (Listener listener : listeners) listener.changed(); }
  void mail() { Services.resolve(Mail.class); }
}
''',
      'ClockOwner.java':
          'class ClockOwner { void load() { Services.resolve(Clock.class); } }',
      'StoreOwner.java':
          'class StoreOwner { void load() { Services.resolve(Store.class); } }',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll([
        'oop-service-locator-dependency',
        'oop-repeated-observer-notification',
      ]),
    );
  });

  test('reports Java dominant boundary bypasses', () {
    final analysis = _analyze({
      'Boundaries.java': '''
class WidgetFactory { Widget make() { return new Widget(); } }
class OrderFacade {
  private final OrderService orders;
  private final PaymentGateway payments;
  private final MailClient mail;
}
class OrderRepository { private final OrderDatabase database; }
class OrderProxy { private final OrderService service; }
''',
      'A.java':
          'class A { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'B.java':
          'class B { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'C.java':
          'class C { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }',
      'Bypass.java': '''
class Bypass {
  Widget make() { return new Widget(); }
  OrderService orders;
  PaymentGateway payments;
  OrderDatabase database;
}
''',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll([
        'oop-factory-bypass',
        'oop-facade-bypass',
        'oop-repository-bypass',
        'oop-proxy-bypass',
      ]),
    );
  });

  test('reports Java repeated mapping and sibling workflow', () {
    final analysis = _analyze({
      'A.java': '''
class A { Target map(Source source) { return new Target(source.getName(), source.getAge(), source.getCity()); } }
class One extends Base {
  @Override
  public void run() { open(); read(); oneStep(); close(); }
}
''',
      'B.java': '''
class B { Target map(Source source) { return new Target(source.getName(), source.getAge(), source.getCity()); } }
class Two extends Base {
  @Override
  public void run() { open(); read(); twoStep(); close(); }
}
''',
      'C.java':
          'class C { Target map(Source source) { return new Target(source.getName(), source.getAge(), source.getCity()); } }',
    });
    expect(
      analysis.findings.map((f) => f.code),
      containsAll([
        'oop-repeated-adapter-mapping',
        'oop-template-workflow-candidate',
      ]),
    );
  });

  test('ignores parallel Java source-flavor workflow copies', () {
    final analysis = _analyze({
      'android/Synchronized.java': '''
class AndroidMap extends Base {
  void run() { open(); read(); androidStep(); close(); }
}
''',
      'jre/Synchronized.java': '''
class JreMap extends Base {
  void run() { open(); read(); jreStep(); close(); }
}
''',
    });
    expect(
      analysis.findings.where(
        (f) => f.code == 'oop-template-workflow-candidate',
      ),
      isEmpty,
    );
  });

  test('ignores comments, strings, partial groups, and contract wrappers', () {
    final analysis = _analyze({
      'Safe.java': '''
interface GatewayContract {}
class Gateway implements GatewayContract {
  private Client client;
  public Result load(Id id) { return client.load(id); }
  public Result save(Id id) { return client.save(id); }
  public Result delete(Id id) { return client.delete(id); }
  public Result refresh(Id id) { return client.refresh(id); }
  public Result inspect(Id id) { return client.inspect(id); }
  String sample() { return "void run(String tenant, int region, boolean active)"; }
}
// class Fake { void run(String tenant, int region, boolean active) {} }
''',
      'PartialSubject.java': '''
class PartialSubject {
  private List<Listener> listeners;
  void add(Listener listener) { listeners.add(listener); }
  void first() { for (Listener listener : listeners) listener.changed(); }
  void second() { for (Listener listener : listeners) listener.changed(); }
  void load() { Services.resolve(Mail.class); }
}
''',
      'PartialStore.java':
          'class PartialStore { void load() { Services.resolve(Store.class); } }',
      'PartialBoundary.java': '''
class SmallFactory { Widget make() { return new Widget(); } }
class FirstUser { SmallFactory factory; }
class SecondUser { SmallFactory factory; }
class PartialMap {
  Target map(Source source) { return new Target(source.getName(), source.getAge()); }
}
''',
      'QuotedBoundary.java': '''
class QuotedBoundary {
  String sample() { return "new Target(source.getName(), source.getAge(), source.getCity())"; }
}
// class HiddenFactory { Widget make() { return new Widget(); } }
''',
    });
    expect(analysis.findings.where((f) => f.code.startsWith('oop-')), isEmpty);
  });
}

LanguageAnalysis _analyze(Map<String, String> sources) =>
    LanguagePluginRegistry.standard()
        .require('java')
        .analyze(sources, const AnalysisConfig(root: '.'));
