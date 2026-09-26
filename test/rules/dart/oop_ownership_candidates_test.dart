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

  test('ignores member comparisons against another instance of this type', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/painter.dart': '''
class AtlasPainter {
  bool shouldRepaint(AtlasPainter oldDelegate) =>
      oldDelegate.document != document ||
      oldDelegate.items != items ||
      oldDelegate.atlases != atlases ||
      oldDelegate.selectedId != selectedId ||
      oldDelegate.viewport != viewport;
}
''',
    });

    expect(findings, isEmpty);
  });

  test(
    'ignores returned Flutter widget composition but retains foreign behavior',
    () {
      final List<Finding> findings = analyze(<String, String>{
        'lib/resource_panel.dart': '''
import 'package:flutter/material.dart';

class ResourcePanel extends StatefulWidget {}

class ResourcePanelState extends State<ResourcePanel> {
  Widget resourceRow(Resource resource) => Card(
    child: Column(
      children: [
        Text(resource.id),
        Text(resource.id),
        Text(resource.path),
        Text(resource.path),
        Text(resource.kind),
        Text(resource.kind),
      ],
    ),
  );

  Widget prepare(Resource resource) {
    resource.load();
    resource.validate();
    resource.save();
    resource.load();
    resource.audit();
    return const SizedBox();
  }
}
''',
      });

      expect(findings, hasLength(1));
      expect(findings.single.code, 'oop-feature-envy');
      expect(
        findings.single.message,
        contains(
          'ResourcePanelState.prepare accesses Resource parameter resource',
        ),
      );
    },
  );

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
