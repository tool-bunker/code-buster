#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;

    const EXPECTED: [&str; 17] = [
        "oop-data-clump",
        "oop-interface-segregation-pressure",
        "oop-refused-bequest",
        "oop-middle-man-delegation",
        "oop-single-use-abstraction",
        "oop-repeated-strategy-dispatch",
        "oop-state-behavior-candidate",
        "oop-feature-envy",
        "oop-service-locator-dependency",
        "oop-repeated-observer-notification",
        "oop-message-chain",
        "oop-factory-bypass",
        "oop-facade-bypass",
        "oop-repository-bypass",
        "oop-proxy-bypass",
        "oop-repeated-adapter-mapping",
        "oop-template-workflow-candidate",
    ];

    #[test]
    fn reports_all_shared_oop_rules_for_csharp_projects() {
        let codes = analyze(&fixture())
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();

        assert_eq!(codes, EXPECTED.into_iter().map(str::to_owned).collect());
    }

    #[test]
    fn ignores_masked_and_below_threshold_evidence() {
        let sources = BTreeMap::from([(
            "Safe.cs".to_owned(),
            r#"
// class Fake { public void Run(string tenant, int region, bool active) { } }
class SafeGateway : IGateway {
  private readonly Client _client;
  public Result Load(Id id) => _client.Load(id);
  public Result Save(Id id) => _client.Save(id);
  public Result Delete(Id id) => _client.Delete(id);
  public Result Refresh(Id id) => _client.Refresh(id);
  public Result Inspect(Id id) => _client.Inspect(id);
  public string Example() => "throw new NotSupportedException()";
  public string RawExample() => """
    class FakeRaw {
      public void Run(string tenant, int region, bool active) { }
    }
    """;
}
class One { public void Run(string tenant, int region, bool active) { } }
class Two { public void Run(int region, string tenant, bool active) { } }
"#
            .to_owned(),
        )]);

        assert!(analyze(&sources).is_empty());
    }
    #[test]
    fn includes_top_level_typescript_functions_in_data_clumps() {
        let sources = BTreeMap::from([
            (
                "first.ts".to_owned(),
                r#"
export function createOrder(
  tenant: string,
  region: number,
  active: string | boolean,
): void {}
class Service {
  update(tenant: string, region: number, active: string | boolean): void {}
}
"#
                .to_owned(),
            ),
            (
                "second.ts".to_owned(),
                r#"
const message = `value doesn't have '${value}'`;
interface Gateway {
  send(tenant: string, region: number, active: string | boolean): void;
}
"#
                .to_owned(),
            ),
        ]);

        let findings = analyze(&sources);
        let finding = findings
            .iter()
            .find(|finding| finding.code == "oop-data-clump")
            .expect("TypeScript data clump must be reported");
        assert_eq!(finding.path, "first.ts");
        assert_eq!(finding.related_files, ["second.ts"]);
        assert_eq!(finding.line, 2);
        assert_eq!(
            finding.message,
            "Parameters tenant, region, active recur together in 3 declarations across 2 files"
        );
    }

    #[test]
    fn does_not_combine_evidence_between_language_analyzers() {
        let sources = BTreeMap::from([
            (
                "One.cs".to_owned(),
                "class One { void Run(string tenant, int region, bool active) {} }".to_owned(),
            ),
            (
                "Two.java".to_owned(),
                "class Two { void run(String tenant, int region, boolean active) {} }".to_owned(),
            ),
            (
                "Three.ts".to_owned(),
                "class Three { run(tenant: string, region: number, active: boolean): void {} }"
                    .to_owned(),
            ),
        ]);

        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
    }

    fn fixture() -> BTreeMap<String, String> {
        [
            (
                "Contracts.cs",
                r#"
public interface IStorage {
  void Read();
  void Write();
  void Delete();
  void Archive();
}
public interface IOne { int Run(int value); }
class OneImpl : IOne {
  public int Run(int value) => value;
}
class OneCaller {
  private OneImpl _one = new OneImpl();
}
"#,
            ),
            (
                "Cold.cs",
                r#"
class ColdStorage : IStorage {
  public void Read() { }
  public void Write() { throw new NotSupportedException(); }
  public void Delete() { throw new NotImplementedException(); }
  public void Archive() { }
}
"#,
            ),
            (
                "ReadOnly.cs",
                r#"
class ReadOnlyStorage : IStorage {
  public void Read() { }
  public void Write() { throw new NotSupportedException(); }
  public void Delete() { }
  public void Archive() { throw new NotImplementedException(); }
}
"#,
            ),
            (
                "Channel.cs",
                r#"
class Channel {
  public virtual void Open() { }
  public virtual void Close() { }
  public virtual void Send() { }
  public virtual void Receive() { }
}
"#,
            ),
            (
                "Input.cs",
                r#"
class InputChannel : Channel {
  public override void Send() { throw new NotSupportedException(); }
  public override void Close() { throw new NotImplementedException(); }
}
"#,
            ),
            (
                "Output.cs",
                r#"
class OutputChannel : Channel {
  public override void Receive() { throw new NotSupportedException(); }
  public override void Open() { throw new NotImplementedException(); }
}
"#,
            ),
            (
                "Create.cs",
                r#"
class CreateService {
  public void Create(string tenant, int region, bool active) { }
  public void Update(string tenant, int region, bool active) { }
}
"#,
            ),
            (
                "Delete.cs",
                r#"
class DeleteService {
  public void Delete(string tenant, int region, bool active) { }
}
"#,
            ),
            (
                "Gateway.cs",
                r#"
class Gateway {
  private readonly Client _client;
  public Result Load(Id id) => _client.Load(id);
  public Result Save(Id id) => _client.Save(id);
  public Result Delete(Id id) => _client.Delete(id);
  public Result Refresh(Id id) => _client.Refresh(id);
  public Result Inspect(Id id) => _client.Inspect(id);
}
"#,
            ),
            (
                "BehaviorA.cs",
                r#"
class StrategyA {
  void Run(Kind k) { switch(k) { case Kind.A: A1(); break; case Kind.B: B1(); break; case Kind.C: C1(); break; } }
}
class StrategyB {
  void Run(Kind k) { switch(k) { case Kind.A: A2(); break; case Kind.B: B2(); break; case Kind.C: C2(); break; } }
}
class Envious {
  void Use(Customer c) { c.Name(); c.Name(); c.Address(); c.Address(); c.Credit(); }
  void Locate() { Services.Resolve<Mail>(); }
}
class Chain {
  void A() { var x = root.A.B.C.D; }
  void B() { var x = root.A.B.C.D; var y = root.E.F.G.H; }
}
"#,
            ),
            (
                "BehaviorB.cs",
                r#"
class StrategyC {
  void Run(Kind k) { switch(k) { case Kind.A: A3(); break; case Kind.B: B3(); break; case Kind.C: C3(); break; } }
}
class LocatorB { void Locate() { Services.Resolve<Clock>(); } }
"#,
            ),
            (
                "BehaviorC.cs",
                "class LocatorC { void Locate() { Services.Resolve<Store>(); } }",
            ),
            (
                "State.cs",
                r#"
class Machine {
  private Status _status;
  void A() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
  void B() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
  void C() { switch(_status) { case Status.Ready: Go(); break; case Status.Busy: Wait(); break; case Status.Done: Stop(); break; } }
}
"#,
            ),
            (
                "Observer.cs",
                r#"
class Subject {
  private List<Listener> listeners;
  void Add(Listener listener) { listeners.Add(listener); }
  void Remove(Listener listener) { listeners.Remove(listener); }
  void A() { foreach (var listener in listeners) listener.Changed(); }
  void B() { foreach (var listener in listeners) listener.Changed(); }
  void C() { foreach (var listener in listeners) listener.Changed(); }
}
"#,
            ),
            (
                "Boundaries.cs",
                r#"
class WidgetFactory { Widget Make() => new Widget(); }
class OrderFacade {
  private OrderService orders;
  private PaymentGateway payments;
  private MailClient mail;
}
class OrderRepository { private OrderDatabase database; }
class OrderProxy { private AuditService service; }
"#,
            ),
            (
                "BoundaryUserA.cs",
                "class UserA { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }",
            ),
            (
                "BoundaryUserB.cs",
                "class UserB { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }",
            ),
            (
                "BoundaryUserC.cs",
                "class UserC { WidgetFactory factory; OrderFacade facade; OrderRepository repository; OrderProxy proxy; }",
            ),
            (
                "BoundaryBypass.cs",
                "class Bypass { Widget Make() => new Widget(); OrderService orders; PaymentGateway payments; OrderDatabase database; AuditService service; }",
            ),
            (
                "MappingA.cs",
                r#"
class MapperA {
  Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City };
}
class MapperB {
  Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City };
}
class WorkflowOne : WorkflowBase {
  public override void Run() { Open(); Read(); OneStep(); Close(); }
}
"#,
            ),
            (
                "MappingB.cs",
                r#"
class MapperC {
  Target Map(Source s) => new Target { Name = s.Name, Age = s.Age, City = s.City };
}
class WorkflowTwo : WorkflowBase {
  public override void Run() { Open(); Read(); TwoStep(); Close(); }
}
"#,
            ),
        ]
        .into_iter()
        .map(|(path, source)| (path.to_owned(), source.to_owned()))
        .collect()
    }

}
