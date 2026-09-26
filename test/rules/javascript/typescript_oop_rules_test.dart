import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  test('reports repeated typed TypeScript parameter concepts', () {
    final List<Finding> findings = _findings({
      'first.ts': '''
export function createOrder(
  tenant: string,
  region: number,
  active: boolean,
): void {}

class Service {
  update(tenant: string, region: number, active: boolean): void {}
}
''',
      'second.ts': '''
interface Gateway {
  send(tenant: string, region: number, active: boolean): void;
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-data-clump');
    expect(findings.single.path, 'first.ts');
    expect(findings.single.relatedFiles, ['second.ts']);
  });

  test('reports TypeScript contract inheritance and delegation pressure', () {
    final findings = _findings({
      'contract.ts': '''
interface Transport {
  open(): void;
  close(): void;
  send(): void;
  receive(): void;
}
class Base {
  open(): void {}
  close(): void {}
  send(): void {}
  receive(): void {}
}
class First implements Transport {
  open(): void {}
  close(): void {}
  send(): void { throw new Error("unsupported"); }
  receive(): void { throw new Error("not implemented"); }
}
class ChildOne extends Base {
  open(): void { throw new Error("unsupported"); }
  close(): void { throw new Error("not implemented"); }
}
''',
      'implementations.ts': '''
class Second implements Transport {
  open(): void { throw new Error("unsupported"); }
  close(): void {}
  send(): void {}
  receive(): void { throw new Error("not implemented"); }
}
class ChildTwo extends Base {
  open(): void { throw new Error("unsupported"); }
  send(): void { throw new Error("not implemented"); }
}
class Gateway {
  constructor(private readonly client: Client) {}
  load(id: string): Result { return this.client.load(id); }
  save(id: string): Result { return this.client.save(id); }
  remove(id: string): Result { return this.client.remove(id); }
  refresh(id: string): Result { return this.client.refresh(id); }
  inspect(id: string): Result { return this.client.inspect(id); }
}
class ArrowGateway {
  constructor(private readonly client: Client) {}
  load = (id: string): Result => this.client.load(id);
  save = (id: string): Result => this.client.save(id);
  remove = (id: string): Result => this.client.remove(id);
  refresh = (id: string): Result => this.client.refresh(id);
  inspect = (id: string): Result => this.client.inspect(id);
}
''',
    });
    expect(
      findings.map((finding) => finding.code),
      containsAll([
        'oop-interface-segregation-pressure',
        'oop-refused-bequest',
        'oop-middle-man-delegation',
      ]),
    );
  });

  test('reports TypeScript behavioral OOP candidates', () {
    final findings = _findings({
      'behavior-a.ts': '''
class FirstStrategy {
  run(kind: Kind): void { switch (kind) { case Kind.a: actA(); case Kind.b: actB(); case Kind.c: actC(); } }
}
class Stateful {
  private state: State;
  first(): void { switch (this.state) { case State.a: one(); case State.b: two(); case State.c: three(); } }
  second(): void { switch (this.state) { case State.a: one(); case State.b: two(); case State.c: three(); } }
  third(): void { switch (this.state) { case State.a: one(); case State.b: two(); case State.c: three(); } }
}
class Envious {
  inspect(customer: Customer): void {
    customer.name; customer.name; customer.address; customer.address; customer.credit;
  }
}
class Subject {
  private listeners: Set<Listener> = new Set();
  add(listener: Listener): void { this.listeners.add(listener); }
  remove(listener: Listener): void { this.listeners.delete(listener); }
  first(): void { for (const listener of this.listeners) listener.changed(); }
  second(): void { for (const listener of this.listeners) listener.changed(); }
  third(): void { for (const listener of this.listeners) listener.changed(); }
}
class LocatorOne { load(): void { Services.resolve<Mail>(); } }
class Chains {
  first(): void { root.account().profile().address().city(); root.account().profile().contact().email(); }
  second(): void { root.order().customer().address().city(); }
}
''',
      'behavior-b.ts': '''
class SecondStrategy {
  run(kind: Kind): void { switch (kind) { case Kind.a: actA(); case Kind.b: actB(); case Kind.c: actC(); } }
}
class ThirdStrategy {
  run(kind: Kind): void { switch (kind) { case Kind.a: actA(); case Kind.b: actB(); case Kind.c: actC(); } }
}
class LocatorTwo { load(): void { Services.resolve<Clock>(); } }
class LocatorThree { load(): void { Services.resolve<Store>(); } }
''',
    });
    expect(
      findings.map((finding) => finding.code),
      containsAll([
        'oop-repeated-strategy-dispatch',
        'oop-state-behavior-candidate',
        'oop-feature-envy',
        'oop-service-locator-dependency',
        'oop-repeated-observer-notification',
        'oop-message-chain',
      ]),
    );
  });

  test('reports TypeScript boundary and workflow candidates', () {
    final findings = _findings({
      'boundaries.ts': '''
class WidgetFactory { make(): Widget { return new Widget(); } }
class OrderFacade {
  private orders: OrderService;
  private payments: PaymentGateway;
  private mail: MailClient;
}
class OrderRepository { private database: OrderDatabase; }
class OrderProxy { private service: OrderService; }
''',
      'users-a.ts': '''
class A { factory: WidgetFactory; facade: OrderFacade; repository: OrderRepository; proxy: OrderProxy; }
class MapperA { map(source: Source): Target { return { name: source.name, age: source.age, city: source.city }; } }
class One extends Workflow { run(): void { open(); read(); oneStep(); close(); } }
''',
      'users-b.ts': '''
class B { factory: WidgetFactory; facade: OrderFacade; repository: OrderRepository; proxy: OrderProxy; }
class MapperB { map(source: Source): Target { return { name: source.name, age: source.age, city: source.city }; } }
class Two extends Workflow { run(): void { open(); read(); twoStep(); close(); } }
''',
      'users-c.ts': '''
class C { factory: WidgetFactory; facade: OrderFacade; repository: OrderRepository; proxy: OrderProxy; }
class MapperC { map(source: Source): Target { return { name: source.name, age: source.age, city: source.city }; } }
''',
      'bypass.ts': '''
class Bypass {
  make(): Widget { return new Widget(); }
  orders: OrderService;
  payments: PaymentGateway;
  database: OrderDatabase;
}
''',
    });
    expect(
      findings.map((finding) => finding.code),
      containsAll([
        'oop-factory-bypass',
        'oop-facade-bypass',
        'oop-repository-bypass',
        'oop-proxy-bypass',
        'oop-repeated-adapter-mapping',
        'oop-template-workflow-candidate',
      ]),
    );
  });

  test('reports a one-operation abstraction constructed once', () {
    final List<Finding> findings = _findings({
      'user_validator.ts': '''
export interface UserValidator {
  validate(email: string): boolean;
}
export class StandardUserValidator implements UserValidator {
  validate(email: string): boolean { return email.includes("@"); }
}
''',
      'user_service.ts': '''
export function processUser(rawEmail: string): string {
  const validator = new StandardUserValidator();
  if (!validator.validate(rawEmail)) throw new Error("Invalid");
  return rawEmail.trim().toLowerCase();
}
''',
    });

    final Finding finding = findings.singleWhere(
      (finding) => finding.code == 'oop-single-use-abstraction',
    );
    expect(finding.path, 'user_validator.ts');
    expect(finding.message, contains('StandardUserValidator'));
    expect(finding.relatedFiles, isEmpty);
  });

  test(
    'keeps abstractions with variation, state, or repeated construction',
    () {
      final List<Finding> findings = _findings({
        'variation.ts': '''
interface Parser { parse(value: string): boolean; }
class JsonParser implements Parser {
  parse(value: string): boolean { return value.includes("{"); }
}
class XmlParser implements Parser {
  parse(value: string): boolean { return value.includes("<"); }
}
''',
        'stateful.ts': '''
interface Counter { count(value: string): number; }
class StatefulCounter implements Counter {
  private total: number = 0;
  count(value: string): number { return this.total + value.length; }
}
new StatefulCounter();
''',
        'reused.ts': '''
interface Checker { check(value: string): boolean; }
class BasicChecker implements Checker {
  check(value: string): boolean { return value.includes("@"); }
}
new BasicChecker();
new BasicChecker();
''',
        'noise.ts': '''
const sample = "interface Fake { run(): void } class Only implements Fake {}";
// interface Hidden { run(): void }
''',
      });

      expect(
        findings.where(
          (finding) => finding.code == 'oop-single-use-abstraction',
        ),
        isEmpty,
      );
    },
  );

  test('ignores TypeScript OOP evidence below project thresholds', () {
    final findings = _findings({
      'safe-a.ts': '''
class SmallFactory { make(): Widget { return new Widget(); } }
class FirstUser { factory: SmallFactory; }
class PartialObserver {
  private listeners: Set<Listener> = new Set();
  add(listener: Listener): void { this.listeners.add(listener); }
  first(): void { for (const listener of this.listeners) listener.changed(); }
  second(): void { for (const listener of this.listeners) listener.changed(); }
}
class PartialLocator { load(): void { Services.resolve<Mail>(); } }
class PartialMapper { map(source: Source): Target { return { name: source.name, age: source.age }; } }
class Decorators {
  first(): MethodDecorator {
    return (target: object, key: string, descriptor: Descriptor) => descriptor;
  }
  second(): MethodDecorator {
    return (target: object, key: string, descriptor: Descriptor) => descriptor;
  }
}
''',
      'safe-b.ts': '''
class SecondUser { factory: SmallFactory; }
class OtherLocator { load(): void { Services.resolve<Clock>(); } }
const sample = "class Fake { run(): void { root.a().b().c().d(); } }";
// class Hidden { run(): void { switch (kind) { case A: a(); case B: b(); case C: c(); } } }
class OtherDecorator {
  create(): MethodDecorator {
    return (target: object, key: string, descriptor: Descriptor) => descriptor;
  }
}
''',
    });
    const oopCodes = <String>{
      'oop-interface-segregation-pressure',
      'oop-refused-bequest',
      'oop-middle-man-delegation',
      'oop-repeated-strategy-dispatch',
      'oop-data-clump',
      'oop-state-behavior-candidate',
      'oop-feature-envy',
      'oop-service-locator-dependency',
      'oop-repeated-observer-notification',
      'oop-message-chain',
      'oop-factory-bypass',
      'oop-facade-bypass',
      'oop-repository-bypass',
      'oop-proxy-bypass',
      'oop-repeated-adapter-mapping',
      'oop-template-workflow-candidate',
    };
    expect(
      findings.where((finding) => oopCodes.contains(finding.code)),
      isEmpty,
    );
  });

  test('requires complete repeated signatures across multiple files', () {
    final List<Finding> findings = _findings({
      'safe.ts': '''
function one(tenant: string, region: number, active: boolean): void {}
function two(tenant: string, region: number): void {}
function inferred(tenant, region, active): void {}
const sample = "function fake(tenant: string, region: number, active: boolean): void {}";
// function hidden(tenant: string, region: number, active: boolean): void {}
''',
      'other.ts': '''
function three(tenant: string, region: number, active: boolean): void {}
''',
    });

    expect(findings, isEmpty);
  });
}

List<Finding> _findings(Map<String, String> sources) =>
    LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(sources, const AnalysisConfig(root: '.'))
        .findings;
