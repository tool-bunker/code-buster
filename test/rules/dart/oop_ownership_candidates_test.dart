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
              'oop-feature-envy',
              'oop-service-locator-dependency',
            }.contains(finding.code),
          )
          .toList();

  test('reports a method dominated by one foreign parameter', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/formatter.dart': '''
class CustomerFormatter {
  String describe(Customer customer) {
    final name = customer.firstName + customer.lastName;
    final address = customer.street + customer.city;
    return '\$name \$address \${customer.postcode} \${customer.city}';
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-feature-envy');
    expect(
      findings.single.message,
      contains('Customer parameter customer 6 times'),
    );
  });

  test('requires five dominant accesses across three foreign members', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/formatter.dart': '''
class CustomerFormatter {
  String describe(Customer customer, Logger logger) {
    logger.start();
    logger.debug();
    logger.trace();
    logger.finish();
    return customer.firstName + customer.lastName +
        customer.street + customer.city;
  }
}
''',
    });

    expect(findings, isEmpty);
  });

  test('reports distributed conventionally named service lookups', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/orders.dart': '''
class OrderController {
  void submit() {
    final repository = getIt<OrderRepository>();
  }
}

class OrderPresenter {
  void show() {
    final analytics = getIt<Analytics>();
  }
}
''',
      'lib/profile.dart': '''
class ProfileController {
  void load() {
    final session = getIt<Session>();
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-service-locator-dependency');
    expect(findings.single.message, contains('3 service types from 3 classes'));
    expect(findings.single.relatedFiles, <String>['lib/profile.dart']);
  });

  test('supports typed get calls on a locator object', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/one.dart': '''
class One {
  void run() => serviceLocator.get<Alpha>();
}
class Two {
  void run() => serviceLocator.get<Beta>();
}
''',
      'lib/two.dart': '''
class Three {
  void run() => serviceLocator.get<Gamma>();
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-service-locator-dependency');
  });

  test(
    'requires three classes, service types, and direct method ownership',
    () {
      final List<Finding> findings = analyze(<String, String>{
        'lib/one.dart': '''
class One {
  void run(Customer customer) {
    schedule(() {
      print(customer.firstName);
      print(customer.lastName);
      print(customer.street);
      print(customer.city);
      print(customer.postcode);
    });
    getIt<Alpha>();
  }
}
''',
        'lib/two.dart': '''
class Two {
  void run() => getIt<Beta>();
}
''',
      });

      expect(findings, isEmpty);
    },
  );
}
