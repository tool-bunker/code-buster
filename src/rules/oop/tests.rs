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
    fn factory_bypass_abstains_when_java_type_identity_is_unresolved() {
        let sources = BTreeMap::from([
            (
                "WidgetFactory.java".to_owned(),
                "class WidgetFactory { Widget make() { return new Widget(); } }".to_owned(),
            ),
            (
                "UserA.java".to_owned(),
                "class UserA { WidgetFactory factory; }".to_owned(),
            ),
            (
                "UserB.java".to_owned(),
                "class UserB { WidgetFactory factory; }".to_owned(),
            ),
            (
                "UserC.java".to_owned(),
                "class UserC { WidgetFactory factory; }".to_owned(),
            ),
            (
                "ProductReference.java".to_owned(),
                "class ProductReference { Widget widget = new Widget(); }".to_owned(),
            ),
        ]);

        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-factory-bypass")
        );
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
    fn ignores_repeated_interface_implementation_signatures() {
        let sources = BTreeMap::from([
            (
                "contract.ts".to_owned(),
                "interface Gateway {\n  send(tenant: string, region: number, active: boolean): void;\n}\nclass Primary {\n  send(tenant: string, region: number, active: boolean): void {}\n}"
                    .to_owned(),
            ),
            (
                "fallback.ts".to_owned(),
                "class Fallback {\n  send(tenant: string, region: number, active: boolean): void {}\n}"
                    .to_owned(),
            ),
        ]);

        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
    }

    #[test]
    fn excludes_ambient_declarations_from_implementation_parameter_clumps() {
        let mut sources = BTreeMap::from([
            (
                "a.ts".to_owned(),
                "export function create(tenant: string, region: number, active: boolean): void {}"
                    .to_owned(),
            ),
            (
                "b.ts".to_owned(),
                "export function update(tenant: string, region: number, active: boolean): void {}"
                    .to_owned(),
            ),
            (
                "types/api.d.ts".to_owned(),
                "export declare function send(tenant: string, region: number, active: boolean): void;\n\
                 export declare function clear(tenant: string, region: number, active: boolean): void;"
                    .to_owned(),
            ),
            (
                "types/window.d.ts".to_owned(),
                "declare var Factory: {\n\
                 new(tenant: string, region: number, active: boolean): () => void;\n\
                 };"
                    .to_owned(),
            ),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
        sources.insert(
            "c.ts".to_owned(),
            "export function archive(tenant: string, region: number, active: boolean): void {}"
                .to_owned(),
        );
        let findings = analyze(&sources);
        let clumps = findings
            .iter()
            .filter(|finding| finding.code == "oop-data-clump")
            .collect::<Vec<_>>();
        assert_eq!(clumps.len(), 1);
        assert_eq!(clumps[0].path, "a.ts");
        assert_eq!(clumps[0].related_files, ["b.ts", "c.ts"]);
    }

    #[test]
    fn ignores_overload_families_concentrated_in_two_type_declarations() {
        let sources = BTreeMap::from([
            (
                "Logger.cs".to_owned(),
                "class Logger {\n void Debug(string message, int eventId, bool flush) {}\n void Info(string message, int eventId, bool flush) {}\n void Error(string message, int eventId, bool flush) {}\n}"
                    .to_owned(),
            ),
            (
                "SilentLogger.cs".to_owned(),
                "class SilentLogger {\n void Debug(string message, int eventId, bool flush) {}\n void Info(string message, int eventId, bool flush) {}\n void Error(string message, int eventId, bool flush) {}\n}"
                    .to_owned(),
            ),
        ]);

        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
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

    #[test]
    fn locates_feature_envy_overloads_at_their_methods() {
        let source = r#"// café

public class Relay
{
  public void
  process(Packet packet, Telemetry message) {
    consume(packet.a(), packet.b(), packet.c(), packet.d(), packet.e(), packet.f());
  }

  public void process(Packet packet, Attributes message) {
    consume(packet.a(), packet.b(), packet.c(), packet.d(), packet.e(), packet.f());
  }

  public void process(Packet packet, int message) { consume(packet.a()); }
}
"#;
        for (path, newline) in [("Relay.java", "\n"), ("Relay.cs", "\r\n")] {
            let sources = BTreeMap::from([(path.to_owned(), source.replace('\n', newline))]);
            let findings = analyze(&sources);
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.code == "oop-feature-envy")
                    .map(|finding| (finding.path.as_str(), finding.line, finding.confidence.as_str()))
                    .collect::<Vec<_>>(),
                [(path, 6, "high"), (path, 10, "high")]
            );
        }
    }

    #[test]
    fn locates_feature_envy_across_typescript_method_forms() {
        let source = r#"class Relay {
  first(packet: Packet) {
    consume(packet.a(), packet.b(), packet.c(), packet.d(), packet.e(), packet.f());
  }
  later = (packet: Packet) =>
    consume(packet.a(), packet.b(), packet.c(), packet.d(), packet.e(), packet.f());
  last(packet: Packet) {
    consume(packet.a(), packet.b(), packet.c(), packet.d(), packet.e(), packet.f());
  }
  tiny(packet: Packet) { consume(packet.a()); }
}
"#;
        let sources = BTreeMap::from([("relay.ts".to_owned(), source.to_owned())]);
        let findings = analyze(&sources);
        let mut lines = findings
            .iter()
            .filter(|finding| finding.code == "oop-feature-envy")
            .map(|finding| finding.line)
            .collect::<Vec<_>>();
        lines.sort_unstable();
        assert_eq!(lines, [2, 5, 7]);
    }

    #[test]
    fn excludes_typescript_object_projection_methods_from_feature_envy() {
        let sources = BTreeMap::from([(
            "context.ts".to_owned(),
            r#"
class Parser {
  private mode = "strict";
  context(input: Input, existing?: Context) {
    return (
      existing || {
      data: input.data,
      path: input.path,
      parent: input.parent,
      source: input.source,
      options: input.options,
      mode: this.mode,
      }
    );
  }
}
"#
            .to_owned(),
        )]);

        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-feature-envy")
        );
    }

    #[test]
    fn counts_override_contracts_once_for_parameter_clumps() {
        let mut sources = BTreeMap::from([
            (
                "Api.java".to_owned(),
                "interface Api {\n void read(String tenant, long entity, Filter filter);\n}"
                    .to_owned(),
            ),
            (
                "Store.java".to_owned(),
                "class Store implements Api {\n\
 @Override\n public void read(String tenant, long entity, Filter filter) {}\n\
 public void lookup(String tenant, long entity, Filter filter) {}\n}"
                    .to_owned(),
            ),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
        sources.insert(
            "Archive.java".to_owned(),
            "class Archive {\n void archive(String tenant, long entity, Filter filter) {}\n}"
                .to_owned(),
        );
        let findings = analyze(&sources);
        let clumps = findings
            .iter()
            .filter(|finding| finding.code == "oop-data-clump")
            .collect::<Vec<_>>();
        assert_eq!(clumps.len(), 1);
        assert_eq!(clumps[0].path, "Api.java");
        assert_eq!(clumps[0].related_files, ["Archive.java", "Store.java"]);
    }

    #[test]
    fn excludes_pure_constructor_forwarding_from_parameter_clumps() {
        let mut sources = BTreeMap::from([
            (
                "Base.java".to_owned(),
                "class Base {\n public Base(String tenant, int region, boolean active) {}\n}"
                    .to_owned(),
            ),
            (
                "First.java".to_owned(),
                "class First extends Base {\n public First(String tenant, int region, boolean active) { super(tenant, region, active); }\n}"
                    .to_owned(),
            ),
            (
                "Second.java".to_owned(),
                "class Second extends Base {\n public Second(String tenant, int region, boolean active) { super(tenant, region, active); }\n}"
                    .to_owned(),
            ),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
        for (path, owner, operation) in [
            ("Audit.java", "Audit", "audit"),
            ("Export.java", "Export", "export"),
        ] {
            sources.insert(
                path.to_owned(),
                format!("class {owner} {{\n void {operation}(String tenant, int region, boolean active) {{}}\n}}"),
            );
        }
        let findings = analyze(&sources);
        let clumps = findings
            .iter()
            .filter(|finding| finding.code == "oop-data-clump")
            .collect::<Vec<_>>();
        assert_eq!(clumps.len(), 1);
        assert_eq!(clumps[0].path, "Audit.java");
        assert_eq!(clumps[0].related_files, ["Base.java", "Export.java"]);
    }

    #[test]
    fn distinguishes_own_type_access_from_foreign_feature_envy() {
        let sources = BTreeMap::from([(
            "Settings.java".to_owned(),
            "class Settings {\n\
 public Settings(Settings input) { input.a(); input.b(); input.c(); input.a(); input.b(); }\n\
 void copy(Settings input) { input.a(); input.b(); input.c(); input.a(); input.b(); }\n\
 void inspect(other.Settings input) { input.a(); input.b(); input.c(); input.a(); input.b(); }\n\
}"
                .to_owned(),
        )]);
        let findings = analyze(&sources);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "oop-feature-envy")
                .map(|finding| (finding.path.as_str(), finding.line))
                .collect::<Vec<_>>(),
            [("Settings.java", 4)]
        );
    }

    #[test]
    fn separates_read_only_builder_mapping_from_foreign_behavior() {
        let sources = BTreeMap::from([(
            "Mapping.java".to_owned(),
            r#"class Mapping { int counter;
 Data copy(Input input) { return Data.builder().a(input.getA()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE()).build(); }
 Data nested(Input input) { return example.Data.newBuilder().a(input.getA().getValue()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE()).ready(input.isReady() ? "yes" : "no").build(); }
 Data behavior(Input input) { return Data.builder().a(input.calculateA()).b(input.calculateB()).c(input.calculateC()).d(input.calculateD()).e(input.calculateE()).build(); }
 Data work(Input input) { audit(); return Data.builder().a(input.getA()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE()).build(); }
 Builder unfinished(Input input) { return Data.builder().a(input.getA()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE()); }
 Data mutation(Input input) { return Data.builder().a(input.getA()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE() + counter++).build(); }
 Data calculation(Input input) { return Data.builder().a(input.getA()).b(input.getB()).c(input.getC()).d(input.getD()).e(transform(input.getE())).build(); }
 Data readModifyWrite(Input input) { return Data.builder().a(input.getAndReset()).b(input.getB()).c(input.getC()).d(input.getD()).e(input.getE()).build(); }
}"#
                .to_owned(),
        )]);
        let findings = analyze(&sources);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "oop-feature-envy")
                .map(|finding| (finding.path.as_str(), finding.line, finding.confidence.as_str()))
                .collect::<Vec<_>>(),
            [
                ("Mapping.java", 4, "high"),
                ("Mapping.java", 5, "high"),
                ("Mapping.java", 6, "high"),
                ("Mapping.java", 7, "high"),
                ("Mapping.java", 8, "high"),
                ("Mapping.java", 9, "high"),
            ]
        );
    }

    #[test]
    fn excludes_constructor_forwarding_with_fixed_defaults_from_clumps() {
        let mut sources = BTreeMap::from([
            ("Range.java".to_owned(), "class Range { long startTs, endTs;\n public Range(String key, long startTs, long endTs) { this.startTs = startTs; this.endTs = endTs; }\n}".to_owned()),
            ("Read.java".to_owned(), "class Read extends Range {\n public Read(String key, long startTs, long endTs) { this(key, startTs, endTs, false); }\n public Read(String key, long startTs, long endTs, boolean flag) { super(key, startTs, endTs); }\n}".to_owned()),
            ("Delete.java".to_owned(), "class Delete extends Range {\n public Delete(String key, long startTs, long endTs) { this(key, startTs, endTs, false, true); }\n public Delete(String key, long startTs, long endTs, boolean first, boolean second) { super(key, startTs, endTs); }\n}".to_owned()),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-data-clump")
        );
        sources.insert(
            "Operations.java".to_owned(),
            "class Operations {\n void query(String key, long startTs, long endTs) {}\n void erase(String key, long startTs, long endTs) {}\n}".to_owned(),
        );
        let findings = analyze(&sources);
        let clumps = findings
            .iter()
            .filter(|finding| finding.code == "oop-data-clump")
            .collect::<Vec<_>>();
        assert_eq!(clumps.len(), 1);
        assert_eq!(clumps[0].path, "Operations.java");
        assert_eq!(clumps[0].related_files, ["Range.java"]);
    }

    #[test]
    fn retains_constructor_clumps_with_derived_arguments_or_extra_work() {
        for body in [
            "this(key, startTs, endTs, endTs - startTs);",
            "super(key, startTs, endTs); initialize();",
            "super(key, endTs, startTs);",
        ] {
            let sources = BTreeMap::from([
                ("Range.java".to_owned(), "class Range { long startTs, endTs;\n public Range(String key, long startTs, long endTs) { this.startTs = startTs; this.endTs = endTs; }\n}".to_owned()),
                ("Read.java".to_owned(), format!("class Read extends Range {{\n public Read(String key, long startTs, long endTs) {{ {body} }}\n public Read(String key, long startTs, long endTs, long interval) {{ super(key, startTs, endTs); }}\n void initialize() {{}}\n}}")),
                ("Delete.java".to_owned(), format!("class Delete extends Range {{\n public Delete(String key, long startTs, long endTs) {{ {body} }}\n public Delete(String key, long startTs, long endTs, long interval) {{ super(key, startTs, endTs); }}\n void initialize() {{}}\n}}")),
            ]);
            let findings = analyze(&sources);
            let clumps = findings
                .iter()
                .filter(|finding| finding.code == "oop-data-clump")
                .collect::<Vec<_>>();
            assert_eq!(clumps.len(), 1, "{body}");
            assert_eq!(clumps[0].path, "Delete.java", "{body}");
            assert_eq!(clumps[0].related_files, ["Range.java", "Read.java"], "{body}");
        }
    }

    #[test]
    fn separates_types_and_completed_builders_from_collaboration_chains() {
        let sources = BTreeMap::from([(
            "Chains.java".to_owned(),
            r#"class Types {
 void one() {
   Class<?> first = org.example.deep.types.Model.class;
   org.example.deep.types.Model value = null;
 }
 void two() { Class<?> second = org.example.deep.types.Other.class; }
}
class Builders {
 void one() { Record.newBuilder().first(1).second(2).build(); }
 void two() {
   Record.builder().first(1).second(2).build();
   Record . toBuilder ( ) . first(1) . second(2) . build ( );
 }
}
class Navigation {
 void one() { consume(root.a.b.c.d); }
 void two() { consume(root.a.b.c.d, root.e.f.g.h); }
}
"#
            .to_owned(),
        )]);
        let mut sources = sources;
        sources.insert(
            "NestedBuilders.java".to_owned(),
            "class NestedBuilders {\n\
 void one() { Record.builder().first(1).second(2).third(3).fourth(makeValue()).build(); }\n\
 void two() {\n\
  Record.newBuilder().first(1).second(2).third(3).fourth(makeValue()).build();\n\
  Record.toBuilder().first(1).second(2).third(3).fourth(makeValue()).build();\n\
 }\n\
}"
                .to_owned(),
        );
        let findings = analyze(&sources);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "oop-message-chain")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [15]
        );
    }

    #[test]
    fn requires_independent_bounded_calls_for_template_workflows() {
        let mut sources = BTreeMap::from([
            (
                "Left.java".to_owned(),
                "class Left extends Base {\n\
 @Override\n void forward() { service.findLeft(Filter.builder().one().two().three().build()); }\n\
 @Override\n void configure(Context ctx) { super.configure(ctx); value = ctx.getLeft().get(ctx.getKey()); }\n\
 @Override\n void run() { open(); read(input.value()); leftStep(); close(); }\n\
}"
                    .to_owned(),
            ),
            (
                "Right.java".to_owned(),
                "class Right extends Base {\n\
 @Override\n void forward() { service.findRight(Filter.builder().one().two().three().build()); }\n\
 @Override\n void configure(Context ctx) { super.configure(ctx); value = ctx.getRight().get(ctx.getKey()); }\n\
 @Override\n void run() { open(); read(input.value()); rightStep(); close(); }\n\
}"
                    .to_owned(),
            ),
        ]);
        let findings = analyze(&sources);
        let workflows = findings
            .iter()
            .filter(|finding| finding.code == "oop-template-workflow-candidate")
            .collect::<Vec<_>>();
        assert_eq!(workflows.len(), 1);
        assert_eq!(workflows[0].path, "Left.java");
        assert_eq!(workflows[0].related_files, ["Right.java"]);

        for (path, owner, step) in [("LongLeft.java", "LongLeft", "left"), ("LongRight.java", "LongRight", "right")] {
            sources.insert(
                path.to_owned(),
                format!("class {owner} extends LongBase {{\n void run() {{ a(); b(); c(); d(); e(); f(); g(); h(); i(); j(); {step}(); }}\n}}"),
            );
        }
        assert_eq!(
            analyze(&sources)
                .iter()
                .filter(|finding| finding.code == "oop-template-workflow-candidate")
                .count(),
            1
        );
    }

    #[test]
    fn preserves_nested_call_differences_when_comparing_workflows() {
        let sources = BTreeMap::from([
            (
                "Left.java".to_owned(),
                "class Left extends Base {\n void run() { open(leftInput()); read(); leftStep(); close(); }\n}"
                    .to_owned(),
            ),
            (
                "Right.java".to_owned(),
                "class Right extends Base {\n void run() { open(rightInput()); read(); rightStep(); close(); }\n}"
                    .to_owned(),
            ),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-template-workflow-candidate")
        );
    }

    #[test]
    fn recognizes_declared_builder_factories_without_exempting_unknown_chains() {
        let mut sources = BTreeMap::from([
            ("Packet.java".to_owned(), "class Packet {\n public static PacketBuilder create() { return new PacketBuilder(); }\n public PacketBuilder transform() { return new PacketBuilder(); }\n}".to_owned()),
            ("Sender.java".to_owned(), "class Sender {\n void first(Packet msg) { Packet.create().a(1).b(2).c(3).build(); msg.transform().a(1).b(2).c(3).build(); }\n void second(Packet msg) { msg.transform().a(1).b(2).c(3).build(); }\n}".to_owned()),
        ]);
        assert!(
            analyze(&sources)
                .iter()
                .all(|finding| finding.code != "oop-message-chain")
        );
        sources.insert("Unknown.java".to_owned(),
            "class Unknown {\n void first(External msg) { msg.transform().a(1).b(2).c(3).build(); msg.transform().a(1).b(2).c(3).build(); }\n void second(External msg) { msg.transform().a(1).b(2).c(3).build(); }\n}".to_owned());
        sources.insert("Unfinished.java".to_owned(),
            "class Unfinished {\n void first() { Packet.create().a(1).b(2).c(3); Packet.create().a(1).b(2).c(3); }\n void second() { Packet.create().a(1).b(2).c(3); }\n}".to_owned());
        let paths = |sources: &BTreeMap<String, String>| {
            analyze(sources)
                .into_iter()
                .filter(|finding| finding.code == "oop-message-chain")
                .map(|finding| finding.path)
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            paths(&sources),
            BTreeSet::from(["Unfinished.java".to_owned(), "Unknown.java".to_owned()])
        );
        sources.insert(
            "other/Packet.java".to_owned(),
            "class Packet {\n public static Other create() { return new Other(); }\n}"
                .to_owned(),
        );
        assert_eq!(
            paths(&sources),
            BTreeSet::from([
                "Sender.java".to_owned(),
                "Unfinished.java".to_owned(),
                "Unknown.java".to_owned(),
            ])
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
