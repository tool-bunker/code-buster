import 'package:code_buster/src/languages/rust/rust_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('extracts Rust modules, use edges, and functions', () {
    final Map<String, String> sources = <String, String>{
      'src/lib.rs': '''
mod network;
use crate::network::Client;

// mod ignored;
// fn ignored() {}
pub fn connect() -> Client {
    let marker = "}";
    /* } fn also_ignored() {} */
    Client::new()
}
''',
      'src/network.rs': '''
pub struct Client;

impl Client {
    pub fn new() -> Self {
        Self
    }
}
''',
    };

    final RustAdapter adapter = RustAdapter();
    final graph = adapter.buildGraph(sources);
    final functions = adapter.functions(sources);

    expect(graph.dependenciesOf('src/lib.rs'), <String>{'src/network.rs'});
    expect(
      functions.map((function) => function.name),
      containsAll(<String>['connect', 'new']),
    );
    expect(
      functions.map((function) => function.name),
      isNot(contains(anyOf('ignored', 'also_ignored'))),
    );
    expect(
      functions.firstWhere((function) => function.name == 'connect').line,
      6,
    );
  });
  test('excludes cfg-test functions from production complexity input', () {
    final functions = RustAdapter().functions(<String, String>{
      'src/lib.rs': '''
fn production() {}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[test]
    fn expensive_fixture() {
        if true {
            for value in values {
                consume(value);
            }
        }
    }
}
''',
    });

    expect(functions.map((function) => function.name), <String>['production']);
  });
}
