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
              'oop-data-clump',
              'oop-repeated-strategy-dispatch',
            }.contains(finding.code),
          )
          .toList();

  test('reports an exact typed parameter group repeated across APIs', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/create.dart': '''
void createAddress(String street, String city, String postalCode) {}
void validateAddress(String postalCode, String street, String city) {}
''',
      'lib/update.dart': '''
void updateAddress(String street, String city, String postalCode) {}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-data-clump');
    expect(findings.single.path, 'lib/create.dart');
    expect(findings.single.message, contains('city, postalCode, street'));
    expect(findings.single.relatedFiles, <String>['lib/update.dart']);
  });

  test('reports repeated callable dispatch over the same variants', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/price.dart': '''
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
''',
      'lib/submit.dart': '''
void submit(PaymentType type) {
  switch (type) {
    case PaymentType.card: submitCard();
    case PaymentType.bank: submitBank();
    case PaymentType.wallet: submitWallet();
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-repeated-strategy-dispatch');
    expect(findings.single.message, contains('3 switches'));
    expect(findings.single.relatedFiles, <String>['lib/submit.dart']);
  });

  test('requires three complete signatures across multiple files', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/one.dart': '''
void first(String street, String city, String postalCode) {}
void second(String street, String city, String postalCode) {}
''',
      'lib/two.dart': '''
void partial(String street, String city) {}
void different(String street, String city, String country) {}
''',
    });

    expect(findings, isEmpty);
  });

  test('ignores incomplete, passive, and differing switch families', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/one.dart': '''
int passive(PaymentType type) {
  switch (type) {
    case PaymentType.card: return 1;
    case PaymentType.bank: return 2;
    case PaymentType.wallet: return 3;
  }
}

void active(PaymentType type) {
  switch (type) {
    case PaymentType.card: card();
    case PaymentType.bank: bank();
    case PaymentType.wallet: wallet();
  }
}
''',
      'lib/two.dart': '''
void different(PaymentType type) {
  switch (type) {
    case PaymentType.card: card();
    case PaymentType.bank: bank();
    case PaymentType.cash: cash();
  }
}
''',
    });

    expect(findings, isEmpty);
  });
  test('ignores local finding emitters and rule registration signatures', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/one.dart': '''
void scan() {
  void add(String id, RuleSeverity severity, String message) {}
}
Rule build(String id, RuleSeverity severity, String group) => Rule();
''',
      'lib/two.dart': '''
void inspect() {
  void add(String id, RuleSeverity severity, String message) {}
}
Rule create(String id, RuleSeverity severity, String group) => Rule();
''',
      'lib/three.dart': '''
void check() {
  void add(String id, RuleSeverity severity, String message) {}
}
Rule register(String id, RuleSeverity severity, String group) => Rule();
''',
    });

    expect(findings, isEmpty);
  });
}
