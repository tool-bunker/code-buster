import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final Map<String, String> sources = <String, String>{
    'Program.cs': sourceFixture('csharp/csharp_adapter_test/Program.cs'),
    'Service.cs': sourceFixture('csharp/csharp_adapter_test/Service.cs'),
    'Unused.cs': 'public class Unused {}',
  };

  test('builds dependencies from project-owned type references', () {
    final DependencyGraph graph = CSharpAdapter().buildGraph(sources);
    expect(graph.dependenciesOf('Program.cs'), <String>['Service.cs']);
    expect(graph.dependenciesOf('Service.cs'), isEmpty);
  });

  test('extracts methods and emits explicitly enabled rules', () {
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      severityOverrides: const <String, RuleSeverity>{
        'cs-async-void': RuleSeverity.warn,
        'cs-thread-sleep': RuleSeverity.info,
        'cs-hardcoded-secret': RuleSeverity.warn,
        'cs-binaryformatter': RuleSeverity.warn,
        'cs-using-inside-namespace': RuleSeverity.warn,
      },
    );
    final CSharpAdapter adapter = CSharpAdapter();
    expect(
      adapter.functions(sources).map((FunctionSource item) => item.name),
      containsAll(<String>['Main', 'Load']),
    );
    final LanguageAnalysis analysis = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(sources, config);
    expect(
      analysis.findings.map((Finding item) => item.code),
      containsAll(config.severityOverrides.keys),
    );
  });

  test('allows async void handlers and overrides but reports other methods', () {
    final LanguageAnalysis
    analysis = LanguagePluginRegistry.standard().require('csharp').analyze(
      <String, String>{
        'Handlers.cs': sourceFixture(
          'csharp/allows_async_void_handlers_and_overrides_but_reports_other_methods/Handlers.cs',
        ),
      },
      const AnalysisConfig(
        root: '.',
        severityOverrides: <String, RuleSeverity>{
          'cs-async-void': RuleSeverity.warn,
        },
      ),
    );

    final List<Finding> findings = analysis.findings
        .where((Finding finding) => finding.code == 'cs-async-void')
        .toList();
    expect(findings.map((Finding finding) => finding.line), <int>[5, 6]);
  });

  test('allows shared HttpClients but reports repeatable construction', () {
    final LanguageAnalysis
    analysis = LanguagePluginRegistry.standard().require('csharp').analyze(
      <String, String>{
        'Clients.cs': sourceFixture(
          'csharp/allows_shared_httpclients_but_reports_repeatable_construction/Clients.cs',
        ),
      },
      const AnalysisConfig(
        root: '.',
        severityOverrides: <String, RuleSeverity>{
          'cs-new-httpclient': RuleSeverity.warn,
        },
      ),
    );

    final List<Finding> findings = analysis.findings
        .where((Finding finding) => finding.code == 'cs-new-httpclient')
        .toList();
    expect(findings.map((Finding finding) => finding.line), <int>[8, 11]);
  });

  test('distinguishes namespace directives from using statements', () {
    final LanguageAnalysis
    analysis = LanguagePluginRegistry.standard().require('csharp').analyze(
      <String, String>{
        'Resource.cs': sourceFixture(
          'csharp/distinguishes_namespace_directives_from_using_statements/Resource.cs',
        ),
      },
      const AnalysisConfig(
        root: '.',
        severityOverrides: <String, RuleSeverity>{
          'cs-using-inside-namespace': RuleSeverity.warn,
        },
      ),
    );

    final List<Finding> findings = analysis.findings
        .where((Finding finding) => finding.code == 'cs-using-inside-namespace')
        .toList();
    expect(findings, hasLength(1));
    expect(findings.single.line, 2);
  });

  test('ignores bitwise enum arguments in boolean conditions', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Conditions.cs': sourceFixture(
              'csharp/ignores_bitwise_enum_arguments_in_boolean_conditions/Conditions.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-non-short-circuit-bool': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-non-short-circuit-bool')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });

  test('ignores legacy API names in comments and strings', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('csharp').analyze(
      <String, String>{
        'Legacy.cs': sourceFixture(
          'csharp/ignores_legacy_api_names_in_comments_and_strings/Legacy.cs',
        ),
      },
      const AnalysisConfig(
        root: '.',
        severityOverrides: <String, RuleSeverity>{
          'cs-remoting-api': RuleSeverity.warn,
          'cs-dcom-api': RuleSeverity.info,
        },
      ),
    ).findings;

    expect(
      findings
          .where((Finding finding) => finding.code == 'cs-remoting-api')
          .map((Finding finding) => finding.line),
      <int>[1, 2],
    );
    expect(
      findings
          .where((Finding finding) => finding.code == 'cs-dcom-api')
          .map((Finding finding) => finding.line),
      <int>[7],
    );
  });

  test('ignores BinaryFormatter API names in comments and strings', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Legacy.cs': sourceFixture(
              'csharp/ignores_binaryformatter_api_names_in_comments_and_strings/Legacy.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-binaryformatter': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-binaryformatter')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[1]);
  });

  test('ignores runtime type aliases in comments', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Alias.cs': sourceFixture(
              'csharp/ignores_runtime_type_aliases_in_comments/Alias.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-runtime-type-alias': RuleSeverity.info,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-runtime-type-alias')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('extracts Allman-style and multiline method declarations', () {
    final List<FunctionSource>
    functions = CSharpAdapter().functions(<String, String>{
      'Logger.cs': sourceFixture(
        'csharp/extracts_allman_style_and_multiline_method_declarations/Logger.cs',
      ),
    });

    expect(functions, hasLength(2));
    expect(functions.map((FunctionSource function) => function.name), <String>[
      'Write',
      'Read',
    ]);
    expect(functions.first.line, 3);
    expect(functions.first.source, contains('Save(message)'));
  });

  test('extracts methods inside C# extension blocks, not the block itself', () {
    final List<FunctionSource>
    functions = CSharpAdapter().functions(<String, String>{
      'Extensions.cs': sourceFixture(
        'csharp/extracts_methods_inside_c_extension_blocks_not_the_block_itself/Extensions.cs',
      ),
    });

    expect(functions.map((FunctionSource function) => function.name), <String>[
      'IsReady',
    ]);
  });

  test('limits security rules to credential and API syntax', () {
    final Map<String, String> securitySources = <String, String>{
      'Security.cs': sourceFixture(
        'csharp/limits_security_rules_to_credential_and_api_syntax/Security.cs',
      ),
    };
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      severityOverrides: const <String, RuleSeverity>{
        'cs-hardcoded-secret': RuleSeverity.warn,
        'cs-cas-api': RuleSeverity.warn,
        'cs-sql-string-build': RuleSeverity.warn,
        'cs-weak-crypto': RuleSeverity.warn,
      },
    );

    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(securitySources, config)
        .findings;
    expect(
      findings.where(
        (Finding finding) => finding.code == 'cs-hardcoded-secret',
      ),
      hasLength(2),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'cs-cas-api'),
      hasLength(1),
    );
    expect(
      findings.where(
        (Finding finding) => finding.code == 'cs-sql-string-build',
      ),
      hasLength(1),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'cs-weak-crypto'),
      hasLength(1),
    );
  });

  test('cs-sql-string-build ignores literal-only query composition', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Queries.cs': sourceFixture(
              'csharp/cs_sql_string_build_ignores_literal_only_query_composition/Queries.cs',
            ),
          },
          AnalysisConfig(
            root: '.',
            severityOverrides: const <String, RuleSeverity>{
              'cs-sql-string-build': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-sql-string-build')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[3, 4]),
    );
  });

  test('cs-sql-string-build accepts provably numeric interpolation', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Queries.cs': sourceFixture(
              'csharp/cs_sql_string_build_accepts_provably_numeric_interpolation/Queries.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-sql-string-build': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-sql-string-build')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[7]);
  });

  test('coalesces public P/Invoke within externally visible files', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'NativeMethods.cs': sourceFixture(
              'csharp/reports_public_p_invoke_only_through_externally_visible_types/NativeMethods.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-public-pinvoke': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-public-pinvoke')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[2]);
  });

  test('distinguishes boolean operators from bitmask expressions', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Conditions.cs': sourceFixture(
              'csharp/distinguishes_boolean_operators_from_bitmask_expressions/Conditions.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-non-short-circuit-bool': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-non-short-circuit-bool')
        .toList();

    expect(findings, hasLength(2));
  });

  test('reports only genuine string accumulation inside loops', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Loops.cs': sourceFixture(
              'csharp/reports_only_genuine_string_accumulation_inside_loops/Loops.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-string-concat-loop': RuleSeverity.info,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-string-concat-loop')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[6, 7]);
  });

  test('requires exact synchronous-wait member names', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('csharp')
        .analyze(
          <String, String>{
            'Results.cs': sourceFixture(
              'csharp/requires_exact_synchronous_wait_member_names/Results.cs',
            ),
          },
          const AnalysisConfig(
            root: '.',
            severityOverrides: <String, RuleSeverity>{
              'cs-sync-over-async': RuleSeverity.warn,
            },
          ),
        )
        .findings
        .where((Finding finding) => finding.code == 'cs-sync-over-async')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3, 4, 5]);
  });

  test('catalogues the complete current C# rule pack', () {
    expect(
      RuleCatalog.all.where((RuleMetadata rule) => rule.id.startsWith('cs-')),
      hasLength(24),
    );
  });
  test('recommends file-scoped namespaces only when configured', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'code_buster_csharp_namespace_',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    const Map<String, String> source = <String, String>{
      'Service.cs': 'namespace Example { public class Service {} }',
    };
    List<Finding> analyze(String projectRoot) =>
        LanguagePluginRegistry.standard()
            .require('csharp')
            .analyze(
              source,
              AnalysisConfig(
                root: projectRoot,
                severityOverrides: const <String, RuleSeverity>{
                  'cs-file-scoped-namespace': RuleSeverity.info,
                },
              ),
            )
            .findings
            .where(
              (Finding finding) => finding.code == 'cs-file-scoped-namespace',
            )
            .toList();

    expect(analyze(root.path), isEmpty);
    File('${root.path}/.editorconfig').writeAsStringSync(
      'csharp_style_namespace_declarations = file_scoped:warning\n',
    );
    expect(analyze(root.path), hasLength(1));
  });
}
