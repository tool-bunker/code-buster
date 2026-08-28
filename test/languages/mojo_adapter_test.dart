import 'package:code_buster/src/languages/mojo/mojo_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('extracts Mojo imports and indentation-delimited functions', () {
    final Map<String, String> sources = <String, String>{
      'main.mojo': '''
from utils import double

def main() raises:
    print(double(21))
''',
      'utils.mojo': '''
def double(value: Int) -> Int:
    return value * 2

def untouched():
    pass
''',
    };

    final MojoAdapter adapter = MojoAdapter();
    final graph = adapter.buildGraph(sources);
    final functions = adapter.functions(sources);

    expect(graph.dependenciesOf('main.mojo'), <String>{'utils.mojo'});
    expect(functions.map((function) => function.name), <String>[
      'main',
      'double',
      'untouched',
    ]);
    expect(
      functions.firstWhere((function) => function.name == 'double').line,
      1,
    );
  });
}
