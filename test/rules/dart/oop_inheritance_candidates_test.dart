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
              'oop-refused-bequest',
              'oop-middle-man-delegation',
            }.contains(finding.code),
          )
          .toList();

  test('reports inherited operations rejected by several subclasses', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/channel.dart': '''
class Channel {
  void connect() {}
  void disconnect() {}
  void send() {}
  void receive() {}
  void flush() {}
}
''',
      'lib/read_only.dart': '''
class ReadOnlyChannel extends Channel {
  @override
  void send() => throw UnsupportedError('read only');
  @override
  void flush() => throw UnsupportedError('read only');
}
''',
      'lib/write_only.dart': '''
class WriteOnlyChannel extends Channel {
  @override
  void receive() => throw UnsupportedError('write only');
  @override
  void flush() => throw UnimplementedError();
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-refused-bequest');
    expect(findings.single.message, contains('3 inherited operations'));
    expect(findings.single.relatedFiles, <String>[
      'lib/read_only.dart',
      'lib/write_only.dart',
    ]);
  });

  test('requires two subclasses rejecting multiple inherited methods', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/channel.dart': '''
class Channel {
  void connect() {}
  void disconnect() {}
  void send() {}
  void receive() {}
}
''',
      'lib/read_only.dart': '''
class ReadOnlyChannel extends Channel {
  @override
  void send() => throw UnsupportedError('read only');
  @override
  void receive() {
    schedule(() => throw UnsupportedError('later'));
  }
}
''',
      'lib/write_only.dart': '''
class WriteOnlyChannel extends Channel {
  @override
  void receive() => throw UnsupportedError('write only');
}
''',
    });

    expect(findings, isEmpty);
  });

  test('reports a class dominated by unchanged delegation', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/orders.dart': '''
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
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-middle-man-delegation');
    expect(findings.single.message, contains('5 of 6 public methods'));
  });

  test('requires unchanged arguments and eighty percent delegation', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/orders.dart': '''
class OrderAccess {
  OrderAccess(this._repository);
  final OrderRepository _repository;

  Order load(String id) => _repository.load(id.trim());
  void save(Order order) => _repository.save(order);
  void remove(String id) => _repository.remove(id);
  bool exists(String id) => _repository.exists(id);
  void clear() => audit.clear();
  String describe() => 'orders';
}
''',
    });

    expect(findings, isEmpty);
  });

  test('excludes declared contract and inheritance boundaries', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/orders.dart': '''
class OrderAccess implements OrderRepository {
  OrderAccess(this._repository);
  final OrderRepository _repository;

  Order load(String id) => _repository.load(id);
  void save(Order order) => _repository.save(order);
  void remove(String id) => _repository.remove(id);
  bool exists(String id) => _repository.exists(id);
  void clear() => _repository.clear();
}
''',
    });

    expect(findings, isEmpty);
  });
}
