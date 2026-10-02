import 'package:analyzer/dart/ast/ast.dart';
import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/languages/rust/rust_adapter.dart';
import 'package:test/test.dart';

void main() {
  const RepositoryAnalysis repository = RepositoryAnalysis();
  const AnalysisConfig config = AnalysisConfig(root: '/project');

  test('validates trivial wrappers through seven language adapters', () {
    for (final _LanguageFixture fixture in _wrapperFixtures) {
      final List<Finding> findings = repository.trivialWrapperFindings(
        functions: fixture.functions(),
        config: config,
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'single-use-trivial-wrapper',
      ], reason: fixture.language);
    }
  });

  test('validates constant arguments through seven language adapters', () {
    for (final _LanguageFixture fixture in _constantArgumentFixtures) {
      final List<Finding> findings = repository.constantArgumentFindings(
        functions: fixture.functions(),
        config: config,
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'constant-argument-parameter',
      ], reason: fixture.language);
      expect(findings.single.message, contains('`enabled`'));
    }
  });

  test('keeps externally visible functions in every validated adapter', () {
    for (final _LanguageFixture fixture in _constantArgumentFixtures) {
      final List<FunctionSource> functions = fixture.extract(<String, String>{
        fixture.path: fixture.publicSource,
      });
      expect(
        repository.constantArgumentFindings(
          functions: functions,
          config: config,
        ),
        isEmpty,
        reason: fixture.language,
      );
    }
  });

  test('validates optional hooks only through supporting adapters', () {
    for (final _LanguageFixture fixture in _customizationHookFixtures) {
      final List<Finding> findings = repository.unusedCustomizationHookFindings(
        functions: fixture.functions(),
        config: config,
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'unused-customization-hook',
      ], reason: fixture.language);
    }
  });

  test('validates unused options through supporting adapters', () {
    for (final _LanguageFixture fixture in _optionalParameterFixtures) {
      final List<Finding> findings = repository.unusedOptionalParameterFindings(
        functions: fixture.functions(),
        config: config,
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'unused-optional-parameter',
      ], reason: fixture.language);
    }
  });

  test('validates single-product factories through supporting adapters', () {
    for (final _LanguageFixture fixture in _singleProductFactoryFixtures) {
      final List<Finding> findings = repository.singleProductFactoryFindings(
        functions: fixture.functions(),
        config: config,
      );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'single-product-factory',
      ], reason: fixture.language);
    }
  });

  test('validates unused configuration through supporting adapters', () {
    for (final _LanguageFixture fixture in _configurationOptionFixtures) {
      final List<Finding> findings = repository
          .unusedConfigurationOptionFindings(
            functions: fixture.functions(),
            config: config,
          );
      expect(findings.map((Finding finding) => finding.code), <String>[
        'unused-configuration-option',
      ], reason: fixture.language);
      expect(findings.single.message, contains('`trace`'));
    }
  });
}

final class _LanguageFixture {
  const _LanguageFixture(this.language, this.path, this.source, this.extract);

  final String language;
  final String path;
  final String source;
  final List<FunctionSource> Function(Map<String, String>) extract;

  List<FunctionSource> functions() => extract(<String, String>{path: source});

  String get publicSource => switch (language) {
    'C++' => source.replaceFirst('static int dispatch', 'int dispatch'),
    'C#' => source.replaceFirst(
      'private static int Dispatch',
      'public static int Dispatch',
    ),
    'Go' => source.replaceAll('dispatch', 'Dispatch'),
    'Java' => source.replaceFirst(
      'private static int dispatch',
      'public static int dispatch',
    ),
    'TypeScript' => source.replaceAll('_dispatch', 'dispatch'),
    'Python' => source.replaceAll('_dispatch', 'dispatch'),
    'Rust' => source.replaceFirst('fn dispatch', 'pub fn dispatch'),
    _ => source,
  };
}

List<FunctionSource> _dart(Map<String, String> sources) {
  final DartSourceParser parser = DartSourceParser();
  return parser.functionsParsed(<String, CompilationUnit>{
    for (final MapEntry<String, String> source in sources.entries)
      source.key: parser
          .parseDetailed(source.value, sourcePath: source.key)
          .unit,
  });
}

List<FunctionSource> _cpp(Map<String, String> sources) =>
    CppAdapter().functions(sources);
List<FunctionSource> _csharp(Map<String, String> sources) =>
    CSharpAdapter().functions(sources);
List<FunctionSource> _go(Map<String, String> sources) =>
    GoAdapter().functions(sources);
List<FunctionSource> _java(Map<String, String> sources) =>
    JavaAdapter().functions(sources);
List<FunctionSource> _typescript(Map<String, String> sources) =>
    JavaScriptFunctionAnalysis().functions(sources);
List<FunctionSource> _python(Map<String, String> sources) =>
    PythonFunctionParser().parse(sources);
List<FunctionSource> _rust(Map<String, String> sources) =>
    RustAdapter().functions(sources);

final List<_LanguageFixture> _wrapperFixtures = <_LanguageFixture>[
  const _LanguageFixture('C++', 'src/wrapper.cpp', '''
static int target(int value) {
  return value;
}
static int wrapper(int value) {
  return target(value);
}
int caller() {
  return wrapper(1);
}
''', _cpp),
  const _LanguageFixture('C#', 'src/Wrapper.cs', '''
class Wrapper {
  private static int Target(int value) {
    return value;
  }
  private static int Wrap(int value) {
    return Target(value);
  }
  public static int Call() {
    return Wrap(1);
  }
}
''', _csharp),
  const _LanguageFixture('Go', 'wrapper.go', '''
package wrapper
func target(value int) int {
  return value
}
func wrap(value int) int {
  return target(value)
}
func Call() int {
  return wrap(1)
}
''', _go),
  const _LanguageFixture('Java', 'src/Wrapper.java', '''
class Wrapper {
  private static int target(int value) {
    return value;
  }
  private static int wrap(int value) {
    return target(value);
  }
  static int call() {
    return wrap(1);
  }
}
''', _java),
  const _LanguageFixture('TypeScript', 'src/wrapper.ts', '''
function _target(value: number) {
  return value;
}
function _wrap(value: number) {
  return _target(value);
}
function call() {
  return _wrap(1);
}
''', _typescript),
  const _LanguageFixture('Python', 'wrapper.py', '''
def _target(value: int) -> int:
    return value

def _wrap(value: int) -> int:
    return _target(value)

def call() -> int:
    return _wrap(1)
''', _python),
  const _LanguageFixture('Rust', 'src/wrapper.rs', '''
fn target(value: i32) -> i32 {
    value
}
fn wrap(value: i32) -> i32 {
    target(value)
}
pub fn call() -> i32 {
    wrap(1)
}
''', _rust),
];

final List<_LanguageFixture> _constantArgumentFixtures = <_LanguageFixture>[
  const _LanguageFixture('C++', 'src/constant.cpp', '''
static int dispatch(int value, bool enabled) {
  return enabled ? value : 0;
}
int first() { return dispatch(1, true); }
int second() { return dispatch(2, true); }
int third() { return dispatch(3, true); }
''', _cpp),
  const _LanguageFixture('C#', 'src/Constant.cs', '''
class Constant {
  private static int Dispatch(int value, bool enabled) {
    return enabled ? value : 0;
  }
  public static int First() { return Dispatch(1, true); }
  public static int Second() { return Dispatch(2, true); }
  public static int Third() { return Dispatch(3, true); }
}
''', _csharp),
  const _LanguageFixture('Go', 'constant.go', '''
package constant
func dispatch(value int, enabled bool) int {
  if enabled { return value }
  return 0
}
func First() int { return dispatch(1, true) }
func Second() int { return dispatch(2, true) }
func Third() int { return dispatch(3, true) }
''', _go),
  const _LanguageFixture('Java', 'src/Constant.java', '''
class Constant {
  private static int dispatch(int value, boolean enabled) {
    return enabled ? value : 0;
  }
  static int first() { return dispatch(1, true); }
  static int second() { return dispatch(2, true); }
  static int third() { return dispatch(3, true); }
}
''', _java),
  const _LanguageFixture('TypeScript', 'src/constant.ts', '''
function _dispatch(value: number, enabled: boolean) {
  return enabled ? value : 0;
}
function first() { return _dispatch(1, true); }
function second() { return _dispatch(2, true); }
function third() { return _dispatch(3, true); }
''', _typescript),
  const _LanguageFixture('Python', 'constant.py', '''
def _dispatch(value: int, enabled: bool) -> int:
    return value if enabled else 0

def first() -> int:
    return _dispatch(1, True)

def second() -> int:
    return _dispatch(2, True)

def third() -> int:
    return _dispatch(3, True)
''', _python),
  const _LanguageFixture('Rust', 'src/constant.rs', '''
fn dispatch(value: i32, enabled: bool) -> i32 {
    if enabled { value } else { 0 }
}
pub fn first() -> i32 { dispatch(1, true) }
pub fn second() -> i32 { dispatch(2, true) }
pub fn third() -> i32 { dispatch(3, true) }
''', _rust),
];

final List<_LanguageFixture> _customizationHookFixtures = <_LanguageFixture>[
  const _LanguageFixture('C#', 'src/Hook.cs', '''
class Hook {
  private static int Render(int value, Func<int, int>? customize = null) {
    return customize?.Invoke(value) ?? value;
  }
  public static int First() { return Render(1); }
  public static int Second() { return Render(2); }
  public static int Third() { return Render(3); }
}
''', _csharp),
  const _LanguageFixture('TypeScript', 'src/hook.ts', '''
type Customizer = (value: number) => number;
function _render(value: number, customize?: Customizer) {
  return customize?.(value) ?? value;
}
function first() { return _render(1); }
function second() { return _render(2); }
function third() { return _render(3); }
''', _typescript),
  const _LanguageFixture('Python', 'hook.py', '''
def _render(value: int, customize=None) -> int:
    return customize(value) if customize else value

def first() -> int:
    return _render(1)

def second() -> int:
    return _render(2)

def third() -> int:
    return _render(3)
''', _python),
];

final List<_LanguageFixture> _optionalParameterFixtures = <_LanguageFixture>[
  const _LanguageFixture('C#', 'src/Option.cs', '''
class Option {
  private static int Save(int value, bool validate = true) {
    return validate ? value : 0;
  }
  public static int First() { return Save(1); }
  public static int Second() { return Save(2); }
  public static int Third() { return Save(3); }
}
''', _csharp),
  const _LanguageFixture('TypeScript', 'src/option.ts', '''
function _save(value: number, validate = true) {
  return validate ? value : 0;
}
function first() { return _save(1); }
function second() { return _save(2); }
function third() { return _save(3); }
''', _typescript),
  const _LanguageFixture('Python', 'option.py', '''
def _save(value: int, validate=True) -> int:
    return value if validate else 0

def first() -> int:
    return _save(1)

def second() -> int:
    return _save(2)

def third() -> int:
    return _save(3)
''', _python),
];

final List<_LanguageFixture> _singleProductFactoryFixtures = <_LanguageFixture>[
  const _LanguageFixture('C++', 'src/factory.cpp', '''
static Product createProduct(int value) {
  return Product(value);
}
void useProduct() {
  auto product = createProduct(1);
}
''', _cpp),
  const _LanguageFixture('C#', 'src/Factory.cs', '''
class Factory {
  private static Product CreateProduct(int value) {
    return new Product(value);
  }
  public static void UseProduct() {
    var product = CreateProduct(1);
  }
}
''', _csharp),
  const _LanguageFixture('Java', 'src/Factory.java', '''
class Factory {
  private static Product createProduct(int value) {
    return new Product(value);
  }
  static void useProduct() {
    Product product = createProduct(1);
  }
}
''', _java),
  const _LanguageFixture('TypeScript', 'src/factory.ts', '''
function _createProduct(value: number) {
  return new Product(value);
}
function useProduct() {
  const product = _createProduct(1);
}
''', _typescript),
  const _LanguageFixture('Python', 'factory.py', '''
def _create_product(value: int):
    return Product(value)

def use_product():
    product = _create_product(1)
''', _python),
];

final List<_LanguageFixture> _configurationOptionFixtures = <_LanguageFixture>[
  const _LanguageFixture('C#', 'src/Configuration.cs', '''
class Configuration {
  private static int Render(int value, RenderOptions options) {
    return options.cache ? value : 0;
  }
  public static int First() {
    return Render(1, new RenderOptions(cache: true, trace: false));
  }
  public static int Second() {
    return Render(2, new RenderOptions(cache: false, trace: true));
  }
  public static int Third() {
    return Render(3, new RenderOptions(cache: true, trace: true));
  }
}
''', _csharp),
  const _LanguageFixture('Dart', 'lib/configuration.dart', '''
int _render(int value, RenderOptions options) {
  return options.cache ? value : 0;
}
int first() =>
    _render(1, RenderOptions(cache: true, trace: false));
int second() =>
    _render(2, RenderOptions(cache: false, trace: true));
int third() =>
    _render(3, RenderOptions(cache: true, trace: true));
''', _dart),
  const _LanguageFixture('TypeScript', 'src/configuration.ts', '''
function _render(value: number, options: RenderOptions) {
  return options.cache ? value : 0;
}
function first() {
  return _render(1, {cache: true, trace: false});
}
function second() {
  return _render(2, {cache: false, trace: true});
}
function third() {
  return _render(3, {cache: true, trace: true});
}
''', _typescript),
  const _LanguageFixture('Python', 'configuration.py', '''
def _render(value: int, options: RenderOptions) -> int:
    return value if options.cache else 0

def first() -> int:
    return _render(1, RenderOptions(cache=True, trace=False))

def second() -> int:
    return _render(2, RenderOptions(cache=False, trace=True))

def third() -> int:
    return _render(3, RenderOptions(cache=True, trace=True))
''', _python),
];
