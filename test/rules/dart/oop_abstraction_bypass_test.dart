import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  List<Finding> analyze(Map<String, String> sources) =>
      LanguagePluginRegistry.standard()
          .require('dart')
          .analyze(sources, const AnalysisConfig(root: '.'))
          .findings
          .where((Finding finding) => finding.code.startsWith('oop-'))
          .toList();

  test('reports direct construction that bypasses a dominant factory', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/factory.dart': '''
class ReportFactory {
  ReportImpl create() => ReportImpl();
}
class ReportImpl {}
''',
      for (var index = 0; index < 3; index++)
        'lib/factory_user_$index.dart': '''
ReportImpl build(ReportFactory factory) => factory.create();
''',
      'lib/direct.dart': 'ReportImpl build() => ReportImpl();',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-factory-bypass');
    expect(findings.single.path, 'lib/direct.dart');
    expect(findings.single.message, contains('ReportFactory'));
  });

  test('reports coordination that bypasses a dominant facade', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/facade.dart': '''
class CheckoutFacade {
  CheckoutFacade(this.inventory, this.payments, this.receipts);
  final InventoryService inventory;
  final PaymentGateway payments;
  final ReceiptWriter receipts;
  void checkout() {}
}
class InventoryService {}
class PaymentGateway {}
class ReceiptWriter {}
''',
      for (var index = 0; index < 3; index++)
        'lib/facade_user_$index.dart': '''
void checkout(CheckoutFacade facade) => facade.checkout();
''',
      'lib/direct.dart': '''
void checkout(InventoryService inventory, PaymentGateway payments) {}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-facade-bypass');
    expect(
      findings.single.message,
      contains('InventoryService, PaymentGateway'),
    );
  });

  test('reports repository and proxy implementation bypasses', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/boundaries.dart': '''
class UserRepository {
  UserRepository(this.database);
  final UserDatabase database;
}
class SearchProxy {
  SearchProxy(this.client);
  final SearchClient client;
}
class UserDatabase {}
class SearchClient {}
''',
      for (var index = 0; index < 3; index++) ...<String, String>{
        'lib/repository_user_$index.dart':
            'void load(UserRepository repository) {}',
        'lib/proxy_user_$index.dart': 'void search(SearchProxy proxy) {}',
      },
      'lib/direct_database.dart': 'void load(UserDatabase database) {}',
      'lib/direct_client.dart': 'void search(SearchClient client) {}',
    });

    expect(findings.map((Finding finding) => finding.code).toSet(), <String>{
      'oop-repository-bypass',
      'oop-proxy-bypass',
    });
  });

  test('requires three abstraction users and dominance over bypasses', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/factory.dart': '''
class ReportFactory {
  ReportImpl create() => ReportImpl();
}
class ReportImpl {}
''',
      'lib/user_a.dart': 'void use(ReportFactory factory) {}',
      'lib/user_b.dart': 'void use(ReportFactory factory) {}',
      'lib/direct_a.dart': 'ReportImpl build() => ReportImpl();',
      'lib/direct_b.dart': 'ReportImpl build() => ReportImpl();',
      'lib/direct_c.dart': 'ReportImpl build() => ReportImpl();',
    });

    expect(findings, isEmpty);
  });

  test('does not treat one facade collaborator or source text as a bypass', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/facade.dart': '''
class CheckoutFacade {
  final InventoryService inventory;
  final PaymentGateway payments;
  final ReceiptWriter receipts;
  CheckoutFacade(this.inventory, this.payments, this.receipts);
}
class InventoryService {}
class PaymentGateway {}
class ReceiptWriter {}
''',
      for (var index = 0; index < 3; index++)
        'lib/user_$index.dart': 'void use(CheckoutFacade facade) {}',
      'lib/inventory_only.dart': '''
// PaymentGateway CheckoutFacade
const description = 'ReceiptWriter';
void inspect(InventoryService inventory) {}
''',
    });

    expect(findings, isEmpty);
  });
}
