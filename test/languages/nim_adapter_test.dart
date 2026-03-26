import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/nim/nim_rule_analysis.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'src/main.nim': sourceFixture('nim/nim_adapter_test/main.nim'),
    'src/service.nim': '''import models
proc run*() = discard
''',
    'src/models.nim': '''type User* = object
  name*: string
''',
  };

  test('resolves relative, dotted, and from imports but ignores stdlib', () {
    final DependencyGraph graph = NimAdapter().buildGraph(sources);
    expect(graph.dependenciesOf('src/main.nim'), <String>[
      'src/models.nim',
      'src/service.nim',
    ]);
    expect(graph.dependenciesOf('src/service.nim'), <String>['src/models.nim']);
  });

  test('emits high-confidence rules across Nim rule groups', () {
    final Iterable<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/risky.nim': sourceFixture(
            'nim/emits_high_confidence_rules_across_nim_rule_groups/risky.nim',
          ),
        })
        .map((Finding item) => item.code);
    expect(
      codes,
      containsAll(<String>[
        'nim-std-import',
        'nim-missing-raises',
        'nim-missing-doc',
        'nim-too-many-parameters',
        'nim-prefer-let',
        'nim-broad-except',
        'nim-cast-usage',
        'nim-return-instead-of-result',
      ]),
    );
  });

  test('detects ported idiomatic, string, suspicious, and zero-cost rules', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'tests/test_patterns.nim': sourceFixture(
            'nim/detects_ported_idiomatic_string_suspicious_and_zero_cost_rules/test_patterns.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-could-be-const',
        'nim-distinct-serialization-asymmetry',
        'nim-divide-by-len-without-empty-check',
        'nim-double-negation',
        'nim-float-test-exact-equality',
        'nim-exported-template-missing-doc',
        'nim-forced-decimal-comma-output',
        'nim-functional-alloc-chain',
        'nim-global-tab-replace',
        'nim-home-dir-strip',
        'nim-hook-overwrites-accumulator',
        'nim-openarray-missing-empty-test',
        'nim-pointer-with-separate-size',
        'nim-readline-without-strip',
        'nim-skip-test-without-comment',
        'nim-state-restore-without-finally',
        'nim-string-serializer-missing-quote',
        'nim-strip-chars-string-set',
        'nim-template-body-state-mutation',
      }),
    );
  });

  test('detects protocol and public mutable API risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/protocol.nim': sourceFixture(
            'nim/detects_protocol_and_public_mutable_api_risks/protocol.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-http-header-contains',
        'nim-protocol-split-without-strip',
        'nim-public-mutable-container-field',
        'nim-websocket-tests-missing-header-variants',
        'nim-websocket-upgrade-fragile',
      }),
    );
  });

  test('detects generic hook and plugin boundary risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/hooks.nim': '''import json
proc dumpHook*[T](value: T) = discard
proc encode*[T](value: T): string = discard
''',
          'src/plugins.nim': sourceFixture(
            'nim/detects_generic_hook_and_plugin_boundary_risks/plugins.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-default-overwrites-context',
        'nim-dynlib-lifetime',
        'nim-dynlib-unchecked-symbol',
        'nim-generic-hook-cross-module-call',
        'nim-generic-hook-missing-doc',
        'nim-generic-hook-same-signature',
        'nim-hook-too-generic',
        'nim-imported-hook-ambiguity-risk',
        'nim-json-heavy-api',
        'nim-plugin-hook-without-kind',
        'nim-proc-only-plugin-api',
      }),
    );
  });

  test('detects hot-loop and repeated parameter design risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/performance.nim': sourceFixture(
            'nim/detects_hot_loop_and_repeated_parameter_design_risks/performance.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-draw-loads-asset',
        'nim-game-loop-allocation',
        'nim-hot-loop-allocation',
        'nim-layout-assumption-undocumented',
        'nim-parameter-cluster-spread',
        'nim-random-in-render',
        'nim-readfile-concat-temp',
        'nim-unbounded-entity-growth',
        'nim-update-blocking-io',
      }),
    );
  });

  test('detects simulation and render-loop correctness risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/game.nim': sourceFixture(
            'nim/detects_simulation_and_render_loop_correctness_risks/game.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-float-equality-physics',
        'nim-input-in-draw',
        'nim-missing-epsilon-distance',
        'nim-mutate-while-iterating',
        'nim-per-frame-string-format',
        'nim-random-in-simulation',
        'nim-render-state-not-restored',
        'nim-save-in-update',
        'nim-sound-every-frame',
        'nim-wall-clock-in-update',
      }),
    );
  });

  test('detects game review lifecycle and architecture risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/review.nim': sourceFixture(
            'nim/detects_game_review_lifecycle_and_architecture_risks/review.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-asset-loaded-not-freed',
        'nim-camera-transform-leak',
        'nim-debug-draw-not-gated',
        'nim-draw-call-in-update',
        'nim-entity-access-after-destroy',
        'nim-hardcoded-screen-size',
        'nim-nil-component-access',
        'nim-o-n-squared-collision',
        'nim-physics-variable-timestep',
        'nim-save-missing-version',
      }),
    );
  });

  test('detects advanced Nim API and module style risks', () {
    final String imports = List<String>.generate(
      16,
      (int index) => 'import package$index',
    ).join('\n');
    final String exports = List<String>.generate(
      26,
      (int index) => 'proc exported$index*() = discard',
    ).join('\n');
    final String templateBody = List<String>.generate(
      21,
      (int index) => '  discard # $index',
    ).join('\n');
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'tests/helpers.nim':
              '''$imports
import std/[a,b,c,d,e,f,g,h,i]
type Public* = object
type Pair* = tuple[x: int, y: int]
type Child* = ref object of RootObj
proc risky*() {.raises: [CatchableError].} = discard
proc rawText*(value: cstring): cstring = discard
proc rawPointer*(value: ptr int): pointer = discard
proc mutable*(): var int = discard
proc initThing*(): Other = discard
template huge*() =
$templateBody
$exports
''',
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-broad-import',
        'nim-constructor-name',
        'nim-cstring-public-api',
        'nim-exported-object-without-doc',
        'nim-god-module',
        'nim-large-template',
        'nim-many-exports',
        'nim-pointer-public-api',
        'nim-public-var-scalar-accessor',
        'nim-raises-catchableerror',
        'nim-ref-object-inheritance',
        'nim-test-naming',
        'nim-tuple-used-as-domain-type',
      }),
    );
  });

  test('detects remaining numeric, capture, command, and ordering risks', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/remaining.nim': sourceFixture(
            'nim/detects_remaining_numeric_capture_command_and_ordering_risks/remaining.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-average-openarray-risk',
        'nim-dt-not-used',
        'nim-float-tests-missing-edge-cases',
        'nim-nested-stdout-capture',
        'nim-tainted-exec',
        'nim-unordered-table-output',
      }),
    );
  });

  test('detects project test coverage and split recursive types', () {
    final Set<String> codes = NimRuleAnalysis()
        .analyze(<String, String>{
          'src/models.nim': sourceFixture(
            'nim/detects_project_test_coverage_and_split_recursive_types/models.nim',
          ),
        })
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'nim-missing-test-for-module',
        'nim-no-test-suite',
        'nim-split-recursive-types',
      }),
    );
  });

  test('reports only real unescaped dynamic markup output sinks', () {
    final List<Finding> findings = NimRuleAnalysis()
        .analyze(<String, String>{
          'tests/xml_output_cohort.nim': sourceFixture(
            'nim/reports_only_real_unescaped_dynamic_markup_output_sinks/xml_output_cohort.nim',
          ),
          'src/unsafe_markup.nim': '''
let userName = readLine(stdin)
echo "<user>", userName, "</user>"
''',
        })
        .where((Finding finding) => finding.code == 'nim-xml-output-unescaped')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'src/unsafe_markup.nim');
    expect(findings.single.line, 2);
  });

  test('extracts indentation-delimited Nim procedures', () {
    final List<FunctionSource> functions = NimAdapter().functions(sources);
    expect(functions.map((FunctionSource item) => item.name), <String>[
      'main',
      'run',
    ]);
    expect(functions.first.source, contains('if true:'));
  });
}
