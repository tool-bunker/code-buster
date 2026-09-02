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
              'oop-repeated-adapter-mapping',
              'oop-template-workflow-candidate',
            }.contains(finding.code),
          )
          .toList();

  test('reports a repeated direct object mapping boundary', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/first_mapper.dart': '''
DomainUser mapForList(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName,
  email: source.emailAddress,
);

DomainUser mapForCache(ApiUser source) => DomainUser(
  email: source.emailAddress,
  id: source.identifier,
  name: source.displayName,
);
''',
      'lib/second_mapper.dart': '''
DomainUser mapForProfile(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName,
  email: source.emailAddress,
);
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-repeated-adapter-mapping');
    expect(findings.single.message, contains('ApiUser to DomainUser'));
    expect(findings.single.relatedFiles, <String>['lib/second_mapper.dart']);
  });

  test('reports sibling overrides with one varying workflow step', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/csv.dart': '''
class CsvProcessor extends DocumentProcessor {
  @override
  void process() {
    load();
    validate();
    transformCsv();
    save();
    notify();
  }
}
''',
      'lib/json.dart': '''
class JsonProcessor extends DocumentProcessor {
  @override
  void process() {
    load();
    validate();
    transformJson();
    save();
    notify();
  }
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-template-workflow-candidate');
    expect(
      findings.single.message,
      contains('vary only transformCsv versus transformJson'),
    );
    expect(findings.single.relatedFiles, <String>['lib/json.dart']);
  });

  test('requires three exact direct mappings in multiple files', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/one.dart': '''
DomainUser mapOne(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName,
  email: source.emailAddress,
);
''',
      'lib/two.dart': '''
DomainUser mapComputed(ApiUser source) => DomainUser(
  id: source.identifier,
  name: source.displayName.trim(),
  email: source.emailAddress,
);
''',
    });

    expect(findings, isEmpty);
  });

  test('ignores unrelated parents and workflows differing twice', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/csv.dart': '''
class CsvProcessor extends DocumentProcessor {
  @override
  void process() {
    load();
    validateCsv();
    transformCsv();
    save();
  }
}
''',
      'lib/json.dart': '''
class JsonProcessor extends DocumentProcessor {
  @override
  void process() {
    load();
    validateJson();
    transformJson();
    save();
  }
}
''',
      'lib/xml.dart': '''
class XmlProcessor extends OtherProcessor {
  @override
  void process() {
    load();
    validateCsv();
    transformXml();
    save();
  }
}
''',
    });

    expect(findings, isEmpty);
  });
}
