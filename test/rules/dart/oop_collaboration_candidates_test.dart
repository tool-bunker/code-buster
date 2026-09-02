import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  List<Finding> analyze(Map<String, String> sources) =>
      LanguagePluginRegistry.standard()
          .require('dart')
          .analyze(sources, const AnalysisConfig(root: '.'))
          .findings
          .where(
            (Finding finding) => <String>{
              'oop-repeated-observer-notification',
              'oop-message-chain',
            }.contains(finding.code),
          )
          .toList();

  test('reports repeated direct observer notification loops', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/model.dart': '''
class Model {
  final List<ModelListener> _listeners = [];

  void addListener(ModelListener listener) => _listeners.add(listener);
  void removeListener(ModelListener listener) => _listeners.remove(listener);

  void rename(String name) {
    for (final listener in _listeners) {
      listener.onChanged();
    }
  }

  void resize(int size) {
    for (final listener in _listeners) {
      listener.onChanged();
    }
  }

  void reset() {
    for (final listener in _listeners) {
      listener.onChanged();
    }
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-repeated-observer-notification');
    expect(findings.single.message, contains('from 3 methods'));
  });

  test('requires registration symmetry and one direct callback per loop', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/model.dart': '''
class Model {
  final List<ModelListener> _listeners = [];

  void addListener(ModelListener listener) => _listeners.add(listener);

  void rename() {
    for (final listener in _listeners) listener.onChanged();
  }
  void resize() {
    for (final listener in _listeners) listener.onChanged();
  }
  void reset() {
    for (final listener in _listeners) {
      listener.onChanged();
      logChange();
    }
  }
}
''',
    });

    expect(findings, isEmpty);
  });

  test('reports repeated deep collaboration chains across methods', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/order_view.dart': '''
class OrderView {
  String countryCode(Order order) {
    return order.customer.address.country.code;
  }

  String currency(Order order) {
    return order.customer.address.country.currency.symbol;
  }

  String taxRegion(Order order) {
    return order.customer.address.country.taxRegion;
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-message-chain');
    expect(findings.single.message, contains('3 collaboration chains'));
    expect(findings.single.message, contains('maximum 5'));
  });

  test('requires four hops, three chains, and two owning methods', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/order_view.dart': '''
class OrderView {
  String country(Order order) {
    final first = order.customer.address.country;
    final second = order.seller.address.country;
    final third = order.store.address.country;
    return '\$first \$second \$third';
  }

  String shortCode(Order order) => order.customer.country.code;
}
''',
    });

    expect(findings, isEmpty);
  });

  test('ignores deep chains owned by nested callbacks', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/order_view.dart': '''
class OrderView {
  void render(Order order) {
    schedule(() {
      print(order.customer.address.country.code);
      print(order.seller.address.country.code);
      print(order.store.address.country.code);
    });
  }

  String title(Order order) => order.customer.name;
}
''',
    });

    expect(findings, isEmpty);
  });
}
