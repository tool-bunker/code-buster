#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{analyze, chain_depths, parse_scope};

    #[test]
    fn reports_dart_middle_man_delegation() {
        let sources = BTreeMap::from([(
            "lib/orders.dart".to_owned(),
            r#"
class OrderAccess {
  OrderAccess(this._repository);
  final OrderRepository _repository;
  Order load(String id) => _repository.load(id);
  void save(Order order) => _repository.save(order);
  void remove(String id) => _repository.remove(id);
  bool exists(String id) => _repository.exists(id);
  void clear() => _repository.clear();
  String describe() => 'orders';
}
"#
            .to_owned(),
        )]);
        assert!(
            analyze(&sources)
                .iter()
                .any(|finding| finding.code == "oop-middle-man-delegation")
        );
    }

    #[test]
    fn scope_parser_keeps_members_separate_across_literal_delimiters() {
        let source = "String value() => ';';\n\
String get label => 'value;{}';\n\
void run() { print('}'); }\n";
        let (_, methods) = parse_scope(source, source, 0, source.len(), Some("Example"));

        assert_eq!(
            methods
                .iter()
                .map(|method| method.name.as_str())
                .collect::<Vec<_>>(),
            ["value", "label", "run"]
        );
    }

    #[test]
    fn feature_envy_uses_complete_methods_and_excludes_map_projections() {
        let sources = BTreeMap::from([(
            "lib/report.dart".to_owned(),
            r#"
class Reporter {
  Map<String, Object> envelope(Report report) => <String, Object>{
    'a': report.alpha,
    'b': report.beta,
    'c': report.gamma,
    'd': report.delta,
    'e': report.epsilon,
  };

  Finding enriched(Finding finding) {
    const brace = '}';
    return Finding(
      finding.alpha,
      finding.beta,
      finding.gamma,
      finding.delta,
      finding.epsilon,
    );
  }
}
"#
            .to_owned(),
        )]);
        let findings = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "oop-feature-envy")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "Reporter.enriched accesses Finding parameter finding 5 times across 5 members"
        );
    }

    #[test]
    fn feature_envy_counts_null_aware_and_cascade_parameter_accesses() {
        let sources = BTreeMap::from([(
            "lib/report.dart".to_owned(),
            r#"
class Reporter {
  void optional(Finding? finding) {
    consume(
      finding?.alpha,
      finding?.beta,
      finding?.gamma,
      finding?.delta,
      finding?.epsilon,
    );
  }

  void cascade(Finding finding) {
    finding
      ..alpha()
      ..beta()
      ..gamma()
      ..delta()
      ..epsilon();
  }

  Path repeatedMembers(Rect rect) {
    consume(rect.left, rect.right, rect.top);
    consume(rect.left, rect.right, rect.top);
    consume(1.0, 2.0, 3.0, 4.0, 5.0);
    Path()
      ..moveTo()
      ..lineTo()
      ..close()
      ..reset()
      ..fill();
    return Path();
  }

  void emitsBrace() {
    consume('{');
  }

  String interpolate(Finding finding, {String Function(String value)? transform}) => '''
${finding.alpha}
${finding.beta}
${finding.gamma}
${finding.delta}
${finding.epsilon}
''';
  void rawPattern() {
    consume(r':\');
  }
}

"#
            .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "oop-feature-envy")
            .map(|finding| finding.message)
            .collect::<Vec<_>>();
        assert_eq!(
            findings,
            [
                "Reporter.optional accesses Finding? parameter finding 5 times across 5 members",
                "Reporter.cascade accesses Finding parameter finding 5 times across 5 members",
                "Reporter.repeatedMembers accesses Rect parameter rect 6 times across 3 members",
                "Reporter.interpolate accesses Finding parameter finding 5 times across 5 members",
            ]
        );
    }

    #[test]
    fn feature_envy_counts_null_aware_accesses_in_the_received_share() {
        let sources = BTreeMap::from([(
            "lib/adapter.dart".to_owned(),
            r#"
class Adapter {
  void translate(Request request, Profile? profile) {
    consume(request.alpha, request.beta, request.gamma);
    consume(request.delta, request.epsilon);
    consume(profile?.alpha, profile?.beta, profile?.gamma);
    consume(profile?.delta, profile?.epsilon);
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
    fn reports_complete_dart_oop_family() {
        let codes = analyze(&complete_fixture())
            .into_iter()
            .map(|finding| finding.code)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            codes,
            [
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
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }
    #[test]
    fn counts_message_chains_in_multiline_generic_classes() {
        let sources = BTreeMap::from([(
            "lib/provider_scope.dart".to_owned(),
            r#"
final class _UncontrolledProviderScopeState
    extends State<UncontrolledProviderScope>
    implements Vsync {
  void Function()? _cancelAsyncTask;

  @override
  void initState() {
    assert(!widget.container.scheduler.flutterVsyncs.contains(this));
    widget.container.scheduler.flutterVsyncs.add(this);
  }

  @override
  void dispose() {
    widget.container.scheduler.flutterVsyncs.remove(this);
  }
}
"#
            .to_owned(),
        )]);

        let findings = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "oop-message-chain")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "_UncontrolledProviderScopeState contains 3 collaboration chains of at least four hops across 2 methods (maximum 4)"
        );
    }

    #[test]
    fn ignores_nested_and_framework_owned_evidence() {
        let sources = source_map(&[
            (
                "lib/callback.dart",
                r#"
abstract class Contract {
  void one();
  void two();
  void three();
  void four();
}
class First implements Contract {
  void one() {}
  void two() {}
  void three() => throw UnsupportedError('direct');
  void four() => throw UnimplementedError();
}
class CallbackOnly implements Contract {
  void one() {}
  void two() {}
  void three() {
    schedule(() => throw UnsupportedError('nested'));
  }
  void four() {}
}
class Owner {
  void inspect(Customer customer) {
    schedule(() {
      print(customer.firstName);
      print(customer.lastName);
      print(customer.street);
      print(customer.city);
      print(customer.postcode);
    });
  }
}
"#,
            ),
            (
                "lib/visitor.dart",
                r#"
class RuleVisitor extends RecursiveAstVisitor<void> {
  void visitMethod(MethodDeclaration node) {
    print(node.parent.root.beginToken.lexeme);
    print(node.body.parent.root.beginToken.lexeme);
  }
  void visitClass(ClassDeclaration node) {
    print(node.parent.root.beginToken.lexeme);
  }
}
"#,
            ),
            (
                "lib/workflow_a.dart",
                r#"
class FirstRule extends SourceRule {
  @override
  void analyze() { load(); validate(); inspectOne(); report(); }
}
"#,
            ),
            (
                "lib/workflow_b.dart",
                r#"
class SecondRule extends SourceRule {
  @override
  void analyze() { load(); validate(); inspectTwo(); report(); }
}
"#,
            ),
        ]);

        assert!(analyze(&sources).is_empty());
    }

    fn complete_fixture() -> BTreeMap<String, String> {
        source_map(&[
            (
                "design/create.dart",
                r#"
void createAddress(String street, String city, String postalCode) {}
void validateAddress(String postalCode, String street, String city) {}
void price(PaymentType type) {
  switch (type) {
    case PaymentType.card: priceCard();
    case PaymentType.bank: priceBank();
    case PaymentType.wallet: priceWallet();
  }
}
void validate(PaymentType type) {
  switch (type) {
    case PaymentType.card: validateCard();
    case PaymentType.bank: validateBank();
    case PaymentType.wallet: validateWallet();
  }
}
"#,
            ),
            (
                "design/update.dart",
                r#"
void updateAddress(String street, String city, String postalCode) {}
void submit(PaymentType type) {
  switch (type) {
    case PaymentType.card: submitCard();
    case PaymentType.bank: submitBank();
    case PaymentType.wallet: submitWallet();
  }
}
"#,
            ),
            (
                "contracts/channel.dart",
                r#"
abstract class Storage {
  void read();
  void write();
  void delete();
  void archive();
}
"#,
            ),
            (
                "contracts/read_only.dart",
                r#"
class ReadOnlyStorage implements Storage {
  void read() {}
  void write() => throw UnsupportedError('read only');
  void delete() => throw UnimplementedError();
  void archive() {}
}
"#,
            ),
            (
                "contracts/append_only.dart",
                r#"
class AppendOnlyStorage implements Storage {
  void read() {}
  void write() {}
  void delete() => throw UnimplementedError();
  void archive() {}
}
"#,
            ),
            (
                "contracts/state.dart",
                r#"
class Order {
  OrderStatus status = OrderStatus.pending;
  void advance() { status = OrderStatus.processing; }
  void render() {
    switch (status) {
      case OrderStatus.pending: showPending();
      case OrderStatus.processing: showProcessing();
      case OrderStatus.complete: showComplete();
    }
  }
  void validate() {
    switch (status) {
      case OrderStatus.pending: validatePending();
      case OrderStatus.processing: validateProcessing();
      case OrderStatus.complete: validateComplete();
    }
  }
  void cancel() {
    switch (status) {
      case OrderStatus.pending: cancelPending();
      case OrderStatus.processing: cancelProcessing();
      case OrderStatus.complete: cancelComplete();
    }
  }
}
"#,
            ),
            (
                "contracts/validator.dart",
                r#"
abstract interface class UserValidator {
  bool validate(String email);
}
class StandardUserValidator implements UserValidator {
  @override
  bool validate(String email) => email.contains('@');
}
"#,
            ),
            (
                "contracts/validator_user.dart",
                "bool process(String email) => StandardUserValidator().validate(email);",
            ),
            (
                "inheritance/base.dart",
                r#"
class Channel {
  void connect() {}
  void disconnect() {}
  void send() {}
  void receive() {}
  void flush() {}
}
"#,
            ),
            (
                "inheritance/read.dart",
                r#"
class ReadChannel extends Channel {
  @override
  void send() => throw UnsupportedError('read only');
  @override
  void flush() => throw UnimplementedError();
}
"#,
            ),
            (
                "inheritance/write.dart",
                r#"
class WriteChannel extends Channel {
  @override
  void receive() => throw UnsupportedError('write only');
  @override
  void flush() => throw UnimplementedError();
}
"#,
            ),
            (
                "inheritance/delegation.dart",
                r#"
class OrderAccess {
  OrderAccess(this._repository);
  final OrderRepository _repository;
  Order load(String id) => _repository.load(id);
  void save(Order order) => _repository.save(order);
  void remove(String id) => _repository.remove(id);
  bool exists(String id) => _repository.exists(id);
  void clear() => _repository.clear();
  String describe() => 'orders';
}
"#,
            ),
            (
                "collaboration/model.dart",
                r#"
class Model {
  final List<ModelListener> _listeners = [];
  void addListener(ModelListener listener) => _listeners.add(listener);
  void removeListener(ModelListener listener) => _listeners.remove(listener);
  void rename() { for (final listener in _listeners) listener.onChanged(); }
  void resize() { for (final listener in _listeners) listener.onChanged(); }
  void reset() { for (final listener in _listeners) listener.onChanged(); }
}
"#,
            ),
            (
                "collaboration/view.dart",
                r#"
class OrderView {
  String country(Order order) => order.customer.address.country.code;
  String currency(Order order) => order.customer.address.country.currency.symbol;
  String region(Order order) => order.customer.address.country.taxRegion;
}
"#,
            ),
            (
                "ownership/formatter.dart",
                r#"
class CustomerFormatter {
  String describe(Customer customer) {
    final name = customer.firstName + customer.lastName;
    final address = customer.street + customer.city;
    return '$name $address ${customer.postcode} ${customer.city}';
  }
}
"#,
            ),
            (
                "ownership/one.dart",
                r#"
class OrderController {
  void submit() { getIt<OrderRepository>(); }
}
class OrderPresenter {
  void show() { getIt<Analytics>(); }
}
"#,
            ),
            (
                "ownership/two.dart",
                "class ProfileController { void load() { getIt<Session>(); } }",
            ),
            (
                "workflow/map_a.dart",
                r#"
DomainUser mapOne(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName,
  email: source.emailAddress,
);
DomainUser mapTwo(ApiUser source) => DomainUser(
  email: source.emailAddress,
  id: source.identifier,
  name: source.displayName,
);
"#,
            ),
            (
                "workflow/map_b.dart",
                r#"
DomainUser mapThree(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName,
  email: source.emailAddress,
);
"#,
            ),
            (
                "workflow/csv.dart",
                r#"
class CsvProcessor extends DocumentProcessor {
  @override
  void process() { load(); validate(); transformCsv(); save(); notify(); }
}
"#,
            ),
            (
                "workflow/json.dart",
                r#"
class JsonProcessor extends DocumentProcessor {
  @override
  void process() { load(); validate(); transformJson(); save(); notify(); }
}
"#,
            ),
            (
                "boundaries/boundaries.dart",
                r#"
class WidgetFactory { Widget make() => Widget(); }
class OrderFacade {
  final OrderService orders;
  final PaymentGateway payments;
  final MailClient mail;
}
class OrderRepository { final OrderDatabase database; }
class OrderProxy { final AuditService service; }
"#,
            ),
            (
                "boundaries/user_a.dart",
                "void use(WidgetFactory a, OrderFacade b, OrderRepository c, OrderProxy d) {}",
            ),
            (
                "boundaries/user_b.dart",
                "void use(WidgetFactory a, OrderFacade b, OrderRepository c, OrderProxy d) {}",
            ),
            (
                "boundaries/user_c.dart",
                "void use(WidgetFactory a, OrderFacade b, OrderRepository c, OrderProxy d) {}",
            ),
            (
                "boundaries/direct.dart",
                r#"
Widget make() => Widget();
void bypass(
  OrderService orders,
  PaymentGateway payments,
  OrderDatabase database,
  AuditService service,
) {}
"#,
            ),
        ])
    }

    #[test]
    fn matches_analyzer_chain_boundaries() {
        let body = r#"
element.getter!.metadata.annotations.map(convert).where(valid);
builderElement!.setter?.formalParameters.first.type;
(parsedLibrary.getFragmentDeclaration(builderElement!.firstFragment)?.node
    as MethodDeclaration?)?.parameters!.parameters.first.childEntities.first.toString();
items.where(valid).map<String>(convert).toList().first;
target.parts.items[index];
schedule((value) => value.first.second.third.fourth.fifth);
"#;

        assert_eq!(chain_depths(body), vec![4, 4, 5, 4]);
    }

    #[test]
    fn excludes_constructor_chains_from_method_collaboration_counts() {
        let sources = BTreeMap::from([(
            "lib/container.dart".to_owned(),
            r#"
class Container {
  Container.from(Parent parent) {
    parent.first.second.third.fourth();
    parent.fifth.sixth.seventh.eighth();
  }

  void inspect(Item item) {
    item.first.second.third.fourth();
  }
}
"#
            .to_owned(),
        )]);

        assert!(
            analyze(&sources)
                .into_iter()
                .all(|finding| finding.code != "oop-message-chain")
        );
    }


    fn source_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
            .collect()
    }
}
