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
              'oop-interface-segregation-pressure',
              'oop-state-behavior-candidate',
            }.contains(finding.code),
          )
          .toList();

  test('reports a contract rejected by multiple implementors', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/channel.dart': '''
abstract class Channel {
  void connect();
  void read();
  void write();
  void delete();
}
''',
      'lib/read_only.dart': '''
class ReadOnlyChannel implements Channel {
  void connect() {}
  void read() {}
  void write() => throw UnsupportedError('read only');
  void delete() => throw UnsupportedError('read only');
}
''',
      'lib/append_only.dart': '''
class AppendOnlyChannel implements Channel {
  void connect() {}
  void read() {}
  void write() {}
  void delete() => throw UnimplementedError();
}
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-interface-segregation-pressure');
    expect(findings.single.path, 'lib/channel.dart');
    expect(findings.single.message, contains('3 rejected implementations'));
    expect(findings.single.relatedFiles, <String>[
      'lib/append_only.dart',
      'lib/read_only.dart',
    ]);
  });

  test('reports repeated behavior over mutable lifecycle state', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/order.dart': '''
class Order {
  OrderStatus status = OrderStatus.pending;

  void advance() {
    status = OrderStatus.processing;
  }

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
''',
    });

    expect(findings, hasLength(1));
    expect(findings.single.code, 'oop-state-behavior-candidate');
    expect(
      findings.single.message,
      contains('mutable status across 3 methods'),
    );
  });

  test('requires multiple rejecting implementations and three failures', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/channel.dart': '''
abstract class Channel {
  void connect();
  void read();
  void write();
  void delete();
}
class CompleteChannel implements Channel {
  void connect() {}
  void read() {}
  void write() {}
  void delete() {}
}
class PartialChannel implements Channel {
  void connect() {}
  void read() {}
  void write() => throw UnsupportedError('no');
  void delete() => throw UnsupportedError('no');
}
''',
    });

    expect(findings, isEmpty);
  });

  test('ignores unsupported throws inside nested callbacks', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/channel.dart': '''
abstract class Channel {
  void connect();
  void read();
  void write();
  void delete();
}
class ReadOnlyChannel implements Channel {
  void connect() {}
  void read() {}
  void write() => throw UnsupportedError('no');
  void delete() => throw UnsupportedError('no');
}
class CallbackChannel implements Channel {
  void connect() {}
  void read() {}
  void write() {
    run(() => throw UnsupportedError('callback only'));
  }
  void delete() {}
}
''',
    });

    expect(findings, isEmpty);
  });

  test('ignores immutable, unassigned, and inconsistent state dispatch', () {
    final List<Finding> findings = analyze(<String, String>{
      'lib/order.dart': '''
class ImmutableOrder {
  final OrderStatus status = OrderStatus.pending;
  void one() => inspect(status);
}

class UnassignedOrder {
  OrderStatus status = OrderStatus.pending;
  void one() {
    switch (status) {
      case OrderStatus.pending: pending();
      case OrderStatus.processing: processing();
      case OrderStatus.complete: complete();
    }
  }
  void two() {
    switch (status) {
      case OrderStatus.pending: pending();
      case OrderStatus.processing: processing();
      case OrderStatus.complete: complete();
    }
  }
  void three() {
    switch (status) {
      case OrderStatus.pending: pending();
      case OrderStatus.cancelled: cancelled();
      case OrderStatus.complete: complete();
    }
  }
}
''',
    });

    expect(findings, isEmpty);
  });
}
