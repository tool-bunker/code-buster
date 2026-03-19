import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'src/main.cpp': sourceFixture('cpp/cpp_adapter_test/main.cpp'),
    'src/widget.hpp': sourceFixture('cpp/cpp_adapter_test/widget.hpp'),
  };

  test('extracts multiline constructors before initializer lists', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'tree.cc': sourceFixture(
        'cpp/extracts_multiline_constructors_before_initializer_lists/tree.cc',
      ),
    });

    expect(functions, hasLength(1));
    expect(functions.single.name, 'Tree');
    expect(functions.single.line, 1);
  });

  test('measures C++ lambdas independently from their enclosing function', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'server.cpp': sourceFixture(
        'cpp/measures_c_lambdas_independently_from_their_enclosing_function/server.cpp',
      ),
    });

    expect(functions, hasLength(2));
    expect(functions[0].name, 'configure');
    expect(const RepositoryAnalysis().measure(functions[0]).cyclomatic, 1);
    expect(functions[1].name, '<lambda>');
    expect(functions[1].line, 2);
    expect(const RepositoryAnalysis().measure(functions[1]).cyclomatic, 3);
  });

  test('ignores functions and branches disabled by preprocessor', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'legacy.c': sourceFixture(
        'cpp/ignores_functions_and_branches_disabled_by_preprocessor/legacy.c',
      ),
    });

    expect(functions, hasLength(1));
    expect(functions.single.name, 'active');
    expect(functions.single.line, 10);
    expect(functions.single.source, isNot(contains('disabled_branch')));
  });

  test('ignores source embedded by locally defined stringifying macros', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'Stringify.h': '''#define STRINGIFY(value) #value
#define STRINGIFY_INDIRECT(value) STRINGIFY(value)
#define SCRIPT_SOURCE(value) @ STRINGIFY_INDIRECT(value)
''',
      'Bridge.m': sourceFixture(
        'cpp/ignores_source_embedded_by_locally_defined_stringifying_macros/Bridge.m',
      ),
    });

    expect(functions, hasLength(1));
    expect(functions.single.name, 'bridgeScript');
    expect(functions.single.line, 2);
    expect(functions.single.source, isNot(contains('window.bridge')));
    expect(const RepositoryAnalysis().measure(functions.single).cyclomatic, 1);
  });

  test('resolves quoted includes and extracts C++ functions', () {
    final CppAdapter adapter = CppAdapter();
    expect(adapter.buildGraph(sources).dependenciesOf('src/main.cpp'), <String>[
      'src/widget.hpp',
    ]);
    final List<FunctionSource> functions = adapter.functions(sources);
    expect(functions.map((FunctionSource item) => item.name), contains('main'));
  });

  test('extracts multiline Objective-C methods before API annotations', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'Responder.mm': sourceFixture(
        'cpp/extracts_multiline_objective_c_methods_before_api_annotations/Responder.mm',
      ),
    });

    expect(functions, hasLength(1));
    expect(functions.single.name, 'handlePress');
  });

  test('resolves Objective-C imports and extracts methods', () {
    final Map<String, String> objectiveC = <String, String>{
      'src/Plugin.m': sourceFixture(
        'cpp/resolves_objective_c_imports_and_extracts_methods/Plugin.m',
      ),
      'src/Codec.h': sourceFixture(
        'cpp/resolves_objective_c_imports_and_extracts_methods/Codec.h',
      ),
    };
    final CppAdapter adapter = CppAdapter();

    expect(
      adapter.buildGraph(objectiveC).dependenciesOf('src/Plugin.m'),
      <String>['src/Codec.h'],
    );
    expect(
      adapter.functions(objectiveC).map((FunctionSource item) => item.name),
      <String>['handleCall'],
    );
    final LanguageAnalysis analysis = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(
          objectiveC,
          AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}),
        );
    expect(
      analysis.findings.map((Finding item) => item.code),
      isNot(contains('cpp-macro-constant')),
    );
  });

  test('reports only literal-valued preprocessor constants', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'assertions.cpp': sourceFixture(
            'cpp/reports_only_literal_valued_preprocessor_constants/assertions.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-macro-constant')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 6);
  });

  test('distinguishes primitive casts from type-only parentheses', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'signatures.cpp': sourceFixture(
            'cpp/distinguishes_primitive_casts_from_type_only_parentheses/signatures.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-cast')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('does not mistake AND expressions for reference parameters', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'color.cpp': sourceFixture(
            'cpp/does_not_mistake_and_expressions_for_reference_parameters/color.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-non-const-ref-param')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 10);
  });

  test('distinguishes C casts from type-only parenthesized syntax', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'callbacks.cpp': sourceFixture(
            'cpp/distinguishes_c_casts_from_type_only_parenthesized_syntax/callbacks.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-cast')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('does not mistake a rand member initializer for C rand', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'random.cpp': sourceFixture(
            'cpp/does_not_mistake_a_rand_member_initializer_for_c_rand/random.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-rand')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5, 6]);
  });

  test('does not extend inline nested types into their enclosing class', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'cache.hpp': sourceFixture(
            'cpp/does_not_extend_inline_nested_types_into_their_enclosing_class/cache.hpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-virtual-no-destructor')
        .toList();

    expect(findings, isEmpty);
  });

  test('does not extract functions embedded in continued string literals', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'script.h': sourceFixture(
        'cpp/does_not_extract_functions_embedded_in_continued_string_literals/script.h',
      ),
    });

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'NativeFunction',
    ]);
  });

  test('does not treat forward declarations as polymorphic classes', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'interfaces.hpp': sourceFixture(
            'cpp/does_not_treat_forward_declarations_as_polymorphic_classes/interfaces.hpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-virtual-no-destructor')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('inherits a virtual destructor from resolved base classes', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'dialog.hpp': sourceFixture(
            'cpp/inherits_a_virtual_destructor_from_resolved_base_classes/dialog.hpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-virtual-no-destructor')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 10);
  });

  test('does not assume an unresolved base lacks a virtual destructor', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'stream.hpp': sourceFixture(
            'cpp/does_not_assume_an_unresolved_base_lacks_a_virtual_destructor/stream.hpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-virtual-no-destructor')
        .toList();

    expect(findings, isEmpty);
  });

  test('finds virtual destructors beyond the first 80 class lines', () {
    final String source = <String>[
      'class LargeInterface {',
      ' public:',
      '  virtual void Draw();',
      ...List<String>.filled(81, '  int value;'),
      '  virtual ~LargeInterface();',
      '};',
    ].join('\n');
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'large.hpp': source,
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-virtual-no-destructor')
        .toList();

    expect(findings, isEmpty);
  });

  test('does not extract Objective-C enum macros as functions', () {
    final List<FunctionSource> functions = CppAdapter().functions(
      <String, String>{
        'Options.h': sourceFixture(
          'cpp/does_not_extract_objective_c_enum_macros_as_functions/Options.h',
        ),
      },
    );

    expect(functions, hasLength(1));
    expect(functions.single.name, 'actualFunction');
  });

  test('reports cast expressions without flagging type-only parentheses', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'types.hpp': sourceFixture(
            'cpp/reports_cast_expressions_without_flagging_type_only_parentheses/types.hpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-cast')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[6, 9]);
  });

  test('does not mistake Objective-C method parameter types for casts', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'observer.mm': sourceFixture(
            'cpp/does_not_mistake_objective_c_method_parameter_types_for_casts/observer.mm',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-cast')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });

  test('accepts structurally explicit Qt object ownership', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'window.cpp': sourceFixture(
            'cpp/accepts_structurally_explicit_qt_object_ownership/window.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-raw-owning-new')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5, 6, 7]);
  });

  test('resolves custom QObject ownership without trusting unknown classes', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'adapter.hpp': sourceFixture(
            'cpp/resolves_custom_qobject_ownership_without_trusting_unknown_classes/adapter.hpp',
          ),
          'window.cpp': sourceFixture(
            'cpp/resolves_custom_qobject_ownership_without_trusting_unknown_classes/window.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-raw-owning-new')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3, 4]);
  });

  test('ignores raw new expressions inside Emscripten JavaScript blocks', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'web.cpp': sourceFixture(
            'cpp/ignores_raw_new_expressions_inside_emscripten_javascript_blocks/web.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-raw-owning-new')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[1, 9]);
  });

  test('emits enabled C++ style and lifetime rules', () {
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      ruleGroups: const <String>{'core', 'style'},
    );
    final Set<String> codes = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(sources, config)
        .findings
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>[
        'cpp-using-namespace-std',
        'cpp-raw-owning-new',
        'cpp-malloc-free',
        'cpp-goto',
        'cpp-virtual-no-destructor',
      ]),
    );
  });

  test('catalogues every C++ rule emitted by the adapter', () {
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      ruleGroups: const <String>{'style'},
    );
    for (final Finding finding
        in LanguagePluginRegistry.standard()
            .require('cpp')
            .analyze(sources, config)
            .findings) {
      expect(RuleCatalog.lookup(finding.code), isNotNull);
    }
    expect(
      RuleCatalog.all.where((RuleMetadata rule) => rule.id.startsWith('cpp-')),
      hasLength(15),
    );
  });
  test('extracts brace-on-next-line functions instead of nested calls', () {
    final List<FunctionSource>
    functions = CppAdapter().functions(<String, String>{
      'worker.c': sourceFixture(
        'cpp/extracts_brace_on_next_line_functions_instead_of_nested_calls/worker.c',
      ),
    });

    expect(functions, hasLength(1));
    expect(functions.single.name, 'process');
    expect(functions.single.line, 1);
  });

  test('distinguishes global unsafe C strings from member APIs', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('cpp')
        .analyze(<String, String>{
          'reader.cpp': sourceFixture(
            'cpp/distinguishes_global_unsafe_c_strings_from_member_apis/reader.cpp',
          ),
        }, AnalysisConfig(root: '.', ruleGroups: const <String>{'style'}))
        .findings
        .where((Finding finding) => finding.code == 'cpp-unsafe-c-string')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[
      2,
      3,
      7,
      8,
      9,
    ]);
  });
}
