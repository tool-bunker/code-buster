import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/dart/dart_mvvm_rules.dart';
import 'package:code_buster/src/rules/dart/dart_rule_analysis.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('reports opt-in MVVM presentation leakage', () {
    final AnalysisConfig config = AnalysisConfig(
      root: '.',
      architectureProfile: 'dart-mvvm',
    );
    final List<Finding> findings = DartMvvmRuleAnalysis().findings(
      <String, String>{
        'lib/models/user_model.dart':
            "import 'package:flutter/widgets.dart';\nclass UserModel {}",
        'lib/view_models/login_view_model.dart': sourceFixture(
          'dart/reports_opt_in_mvvm_presentation_leakage/login_view_model.dart',
        ),
      },
      config,
    );

    expect(
      findings.map((Finding finding) => finding.code),
      containsAll(<String>[
        'mvvm-model-imports-ui',
        'mvvm-viewmodel-ui-context',
        'mvvm-viewmodel-returns-widget',
        'mvvm-viewmodel-performs-navigation',
      ]),
    );
  });

  test('does not run MVVM checks without the profile', () {
    expect(
      DartMvvmRuleAnalysis().findings(<String, String>{
        'lib/view_models/a.dart': 'class A { BuildContext? context; }',
      }, const AnalysisConfig(root: '.')),
      isEmpty,
    );
  });

  test('finds Dart style suspicious security and idiomatic risks', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/risky.dart': sourceFixture(
        'dart/finds_dart_style_suspicious_security_and_idiomatic_risks/risky.dart',
      ),
    }, maxLineLength: 20);

    final Set<String> codes = findings
        .map((Finding finding) => finding.code)
        .toSet();
    expect(
      codes,
      containsAll(<String>{
        'dart-dynamic',
        'dart-print',
        'dart-late-mutable',
        'dart-insecure-random',
        'dart-process-shell',
        'dart-broad-catch',
        'tab-indent',
        'trailing-whitespace',
        'long-line',
      }),
    );
    expect(
      findings
          .singleWhere(
            (Finding finding) => finding.code == 'dart-process-shell',
          )
          .severity,
      RuleSeverity.warn,
    );
  });

  test('allows print as command-line entrypoint output', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'tool/report.dart': sourceFixture(
        'dart/allows_print_as_command_line_entrypoint_output/report.dart',
      ),
      'lib/application.dart': '''
void main() {
  print('application diagnostic');
}
''',
    });

    final List<Finding> printFindings = findings
        .where((Finding finding) => finding.code == 'dart-print')
        .toList();
    expect(printFindings, hasLength(2));
    expect(
      printFindings.map((Finding finding) => finding.path),
      containsAll(<String>['tool/report.dart', 'lib/application.dart']),
    );
  });

  test('reports only mutable late declarations', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/declarations.dart': sourceFixture(
        'dart/reports_only_mutable_late_declarations/declarations.dart',
      ),
    });

    final List<Finding> lateMutable = findings
        .where((Finding finding) => finding.code == 'dart-late-mutable')
        .toList();
    expect(lateMutable, hasLength(1));
    expect(lateMutable.single.line, 6);
  });

  test('ignores map lookups guarded by iteration over the same keys', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/null_assertions.dart': sourceFixture(
        'dart/ignores_map_lookups_guarded_by_iteration_over_the_same_keys/null_assertions.dart',
      ),
    });

    final List<Finding> assertions = findings
        .where((Finding finding) => finding.code == 'dart-null-assertion')
        .toList();
    expect(assertions, hasLength(1));
    expect(assertions.single.line, 1);
  });

  test('accepts guaranteed whole-match access but reports capture access', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/matches.dart': '''
String whole(Match match) => match.group(0)!;
String capture(Match match) => match.group(1)!;
''',
    });

    final List<Finding> assertions = findings
        .where((Finding finding) => finding.code == 'dart-null-assertion')
        .toList();
    expect(assertions, hasLength(1));
    expect(assertions.single.line, 2);
  });

  test('ignores unwrappable comments, directives, and multiline strings', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/layout.dart': sourceFixture(
        'dart/ignores_unwrappable_comments_directives_and_multiline_strings/layout.dart',
      ),
    }, maxLineLength: 40);

    final List<Finding> longLines = findings
        .where((Finding finding) => finding.code == 'long-line')
        .toList();
    expect(longLines, hasLength(1));
    expect(longLines.single.line, 6);
  });

  test('preserves whitespace that is part of multiline string content', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/message.dart':
          "/// columns\tremain aligned\nfinal message = '''\ncontent  \n''';\n",
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'trailing-whitespace' ||
            finding.code == 'tab-indent',
      ),
      isEmpty,
    );
  });

  test(
    'does not treat tabs embedded in generated project text as indentation',
    () {
      final List<Finding>
      findings = DartRuleAnalysis().findings(<String, String>{
        'lib/project.dart':
            "const line = '  ${String.fromCharCode(9)}project file content';\n",
      });

      expect(
        findings.where((Finding finding) => finding.code == 'tab-indent'),
        isEmpty,
      );
    },
  );

  test('reports unreachable statements after unconditional flow by default', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/storage.dart': sourceFixture(
        'dart/reports_unreachable_statements_after_unconditional_flow_by_default/storage.dart',
      ),
    }, config: const AnalysisConfig(root: '.'));

    final Finding finding = findings.singleWhere(
      (Finding item) => item.code == 'dart-unreachable-statement',
    );
    expect(finding.line, 3);
    expect(finding.confidence, 'high');
  });

  test('does not flag a typed HTTPS process invocation with typed catch', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/safe.dart': sourceFixture(
        'dart/does_not_flag_a_typed_https_process_invocation_with_typed_catch/safe.dart',
      ),
    });

    expect(
      findings.where((Finding finding) => finding.code.startsWith('dart-')),
      isEmpty,
    );
  });
  test('requires credential-like entropy for hardcoded secrets', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/secrets.dart': sourceFixture(
        'dart/requires_credential_like_entropy_for_hardcoded_secrets/secrets.dart',
      ),
    });

    final List<Finding> secrets = findings
        .where((Finding finding) => finding.code == 'dart-hardcoded-secret')
        .toList();
    expect(secrets, hasLength(2));
  });

  test('does not treat GraphQL documents as hardcoded secrets', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/account_queries.dart': sourceFixture(
        'dart/does_not_treat_graphql_documents_as_hardcoded_secrets/account_queries.dart',
      ),
    });

    expect(
      findings
          .where((Finding finding) => finding.code == 'dart-hardcoded-secret')
          .map((Finding finding) => finding.line),
      <int>[6],
    );
  });

  test('accepts numbered fixture labels without hiding test credentials', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'packages/demo/test/show_instance_test.dart': '''
const showToken = 'show-token-3165';
const accessToken = '0123456789abcdef';
''',
    });

    expect(
      findings
          .where((Finding finding) => finding.code == 'dart-hardcoded-secret')
          .map((Finding finding) => finding.line),
      <int>[2],
    );
  });

  test('finds security lifecycle Flutter and JSON contract risks', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/advanced.dart': sourceFixture(
        'dart/finds_security_lifecycle_flutter_and_json_contract_risks/advanced.dart',
      ),
    });

    expect(
      findings.map((Finding finding) => finding.code).toSet(),
      containsAll(<String>{
        'dart-bad-certificate-callback',
        'dart-controller-not-disposed',
        'dart-catch-return-null',
        'dart-catch-without-stack-trace',
        'dart-json-cast-without-validation',
        'dart-http-client-not-closed',
        'dart-iosink-not-closed',
        'dart-json-serialization-asymmetry',
        'dart-path-traversal',
        'dart-process-untrusted-argument',
        'dart-sensitive-data-logging',
        'dart-sql-interpolation',
        'dart-throw-string',
        'flutter-future-created-in-build',
        'flutter-global-key-created-in-build',
        'flutter-listener-without-remove',
        'flutter-set-state-after-await',
        'flutter-stream-created-in-build',
      }),
    );
  });

  test('allows explicit nullable parsing and cache fallbacks', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/fallbacks.dart': sourceFixture(
        'dart/allows_explicit_nullable_parsing_and_cache_fallbacks/fallbacks.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-catch-return-null',
      ),
      isEmpty,
    );
  });

  test('scopes JSON asymmetry checks to exact serialization methods', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/product.dart': sourceFixture(
        'dart/scopes_json_asymmetry_checks_to_exact_serialization_methods/product.dart',
      ),
      'lib/sync_service.dart': sourceFixture(
        'dart/scopes_json_asymmetry_checks_to_exact_serialization_methods/sync_service.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'dart-json-serialization-asymmetry',
      ),
      isEmpty,
    );
  });

  test('recognizes validated JSON reader helpers', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/model.dart': sourceFixture(
        'dart/recognizes_validated_json_reader_helpers/model.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'dart-json-serialization-asymmetry',
      ),
      isEmpty,
    );
  });

  test('allows broad catches that transparently forward failures', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/forwarding.dart': sourceFixture(
        'dart/allows_broad_catches_that_transparently_forward_failures/forwarding.dart',
      ),
    });

    final List<Finding> catches = findings
        .where((Finding finding) => finding.code == 'dart-broad-catch')
        .toList();
    expect(catches, hasLength(1));
    expect(catches.single.line, 20);
  });

  test('allows SQL interpolation from literal const String declarations', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/schema.dart': sourceFixture(
        'dart/allows_sql_interpolation_from_literal_const_string_declarations/schema.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-sql-interpolation',
      ),
      isEmpty,
    );
  });

  test('retains SQL findings for runtime and shadowed interpolation', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/queries.dart': sourceFixture(
        'dart/retains_sql_findings_for_runtime_and_shadowed_interpolation/queries.dart',
      ),
    });

    expect(
      findings
          .where((Finding finding) => finding.code == 'dart-sql-interpolation')
          .map((Finding finding) => finding.line),
      <int>[4, 9, 13],
    );
  });

  test('allows JSON casts dominated by matching type tests', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/guarded_json.dart': sourceFixture(
        'dart/allows_json_casts_dominated_by_matching_type_tests/guarded_json.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'dart-json-cast-without-validation',
      ),
      isEmpty,
    );
  });

  test('retains JSON cast findings for mismatched and missing guards', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/unguarded_json.dart': sourceFixture(
        'dart/retains_json_cast_findings_for_mismatched_and_missing_guards/unguarded_json.dart',
      ),
    });

    expect(
      findings
          .where(
            (Finding finding) =>
                finding.code == 'dart-json-cast-without-validation',
          )
          .map((Finding finding) => finding.line),
      <int>[3, 6, 8],
    );
  });

  test('allows GlobalKey creation in deferred build callbacks', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/memoized.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/memoized.dart',
      ),
      'lib/memoized_block.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/memoized_block.dart',
      ),
      'lib/event_callback.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/event_callback.dart',
      ),
      'lib/assigned_callback.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/assigned_callback.dart',
      ),
      'lib/positional_callback.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/positional_callback.dart',
      ),
      'lib/direct.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/direct.dart',
      ),
      'lib/unrelated.dart': sourceFixture(
        'dart/allows_globalkey_creation_in_deferred_build_callbacks/unrelated.dart',
      ),
    });

    expect(
      findings
          .where(
            (Finding finding) =>
                finding.code == 'flutter-global-key-created-in-build',
          )
          .map((Finding finding) => finding.path)
          .toSet(),
      <String>{'lib/direct.dart', 'lib/unrelated.dart'},
    );
  });

  test('limits lifecycle findings to owned disposable fields', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/resources.dart': sourceFixture(
        'dart/limits_lifecycle_findings_to_owned_disposable_fields/resources.dart',
      ),
    });

    const Set<String> resourceCodes = <String>{
      'dart-controller-not-disposed',
      'dart-http-client-not-closed',
      'dart-timer-not-cancelled',
    };
    expect(
      findings.where((Finding finding) => resourceCodes.contains(finding.code)),
      isEmpty,
    );
  });

  test('does not treat a self-typed singleton as an owned HTTP client', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/http_client.dart': sourceFixture(
        'dart/does_not_treat_a_self_typed_singleton_as_an_owned_http_client/http_client.dart',
      ),
    });

    final List<Finding> clients = findings
        .where(
          (Finding finding) => finding.code == 'dart-http-client-not-closed',
        )
        .toList();
    expect(clients, hasLength(1));
    expect(clients.single.message, contains('`_client`'));
  });

  test('does not require analyzer configuration without Dart sources', () {
    final List<Finding> findings = DartRuleAnalysis().findings(
      <String, String>{},
      config: AnalysisConfig(root: Directory.systemTemp.path),
    );

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-recommended-lints-missing',
      ),
      isEmpty,
    );
  });

  test('ignores credential words that occur only in log text', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/logging.dart': sourceFixture(
        'dart/ignores_credential_words_that_occur_only_in_log_text/logging.dart',
      ),
    });

    final List<Finding> sensitive = findings
        .where(
          (Finding finding) => finding.code == 'dart-sensitive-data-logging',
        )
        .toList();
    expect(sensitive, hasLength(1));
    expect(sensitive.single.line, 3);
  });

  test('pairs listener lifecycle calls by AST receiver', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/listeners.dart': sourceFixture(
        'dart/pairs_listener_lifecycle_calls_by_ast_receiver/listeners.dart',
      ),
    });

    final List<Finding> listenerFindings = findings
        .where(
          (Finding finding) =>
              finding.code == 'flutter-listener-without-remove',
        )
        .toList();
    expect(listenerFindings, hasLength(1));
    expect(listenerFindings.single.message, contains('`other`'));
  });

  test('accepts JSON casts protected by a corrupt-input fallback', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/cache_decode.dart': sourceFixture(
        'dart/accepts_json_casts_protected_by_a_corrupt_input_fallback/cache_decode.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'dart-json-cast-without-validation',
      ),
      isEmpty,
    );
  });

  test('reports JSON decoders used outside a fallback', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/cache_decode.dart': sourceFixture(
        'dart/reports_json_decoders_used_outside_a_fallback/cache_decode.dart',
      ),
    });

    expect(
      findings
          .where(
            (Finding finding) =>
                finding.code == 'dart-json-cast-without-validation',
          )
          .single
          .line,
      2,
    );
  });

  test(
    'limits set-state-after-await to Flutter state calls on reachable async paths',
    () {
      final List<Finding>
      findings = DartRuleAnalysis().findings(<String, String>{
        'lib/state.dart': sourceFixture(
          'dart/limits_set_state_after_await_to_flutter_state_calls_on_reachable_async/state.dart',
        ),
      });

      expect(
        findings
            .where(
              (Finding finding) =>
                  finding.code == 'flutter-set-state-after-await',
            )
            .map((Finding finding) => finding.line),
        <int>[10, 17],
      );
    },
  );

  test('does not report advanced risks when ownership and inputs are safe', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/safe_advanced.dart': sourceFixture(
        'dart/does_not_report_advanced_risks_when_ownership_and_inputs_are_safe/safe_advanced.dart',
      ),
    });

    const Set<String> advanced = <String>{
      'dart-bad-certificate-callback',
      'dart-controller-not-disposed',
      'dart-catch-return-null',
      'dart-catch-without-stack-trace',
      'dart-path-traversal',
      'dart-http-client-not-closed',
      'dart-iosink-not-closed',
      'dart-isolate-not-terminated',
      'dart-process-untrusted-argument',
      'dart-sensitive-data-logging',
      'dart-sql-interpolation',
      'dart-timer-not-cancelled',
      'dart-throw-string',
      'flutter-future-created-in-build',
      'flutter-global-key-created-in-build',
      'flutter-listener-without-remove',
      'flutter-set-state-after-await',
      'flutter-stream-created-in-build',
    };
    expect(
      findings.where((Finding finding) => advanced.contains(finding.code)),
      isEmpty,
    );
  });

  test('requires resource ownership and accepts optional disposal', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/lifecycle.dart': sourceFixture(
        'dart/requires_resource_ownership_and_accepts_optional_disposal/lifecycle.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'dart-controller-not-disposed' ||
            finding.code == 'dart-receive-port-not-closed',
      ),
      isEmpty,
    );
  });

  test('reports only controller fields constructed by the class', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/controller_ownership.dart': sourceFixture(
        'dart/reports_only_controller_fields_constructed_by_the_class/controller_ownership.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-controller-not-disposed',
      ),
      hasLength(1),
    );
  });

  test('finds resource async accessibility and loop risks', () {
    final List<Finding> risky = DartRuleAnalysis().findings(<String, String>{
      'lib/more_risks.dart': sourceFixture(
        'dart/finds_resource_async_accessibility_and_loop_risks/more_risks.dart',
      ),
    });

    expect(
      risky.map((Finding finding) => finding.code).toSet(),
      containsAll(<String>{
        'dart-random-access-file-not-closed',
        'dart-receive-port-not-closed',
        'dart-regexp-created-in-loop',
        'dart-repeated-iterable-traversal',
        'dart-string-concat-in-loop',
        'dart-synchronous-file-io-in-async',
        'flutter-gesture-semantic-gap',
        'flutter-unbounded-scrollable',
      }),
    );

    final List<Finding> safe = DartRuleAnalysis().findings(<String, String>{
      'lib/more_safe.dart': sourceFixture(
        'dart/finds_resource_async_accessibility_and_loop_risks/more_safe.dart',
      ),
    });
    const Set<String> newRules = <String>{
      'dart-random-access-file-not-closed',
      'dart-receive-port-not-closed',
      'dart-regexp-created-in-loop',
      'dart-repeated-iterable-traversal',
      'dart-string-concat-in-loop',
      'dart-synchronous-file-io-in-async',
      'flutter-gesture-semantic-gap',
      'flutter-unbounded-scrollable',
    };
    expect(
      safe.where((Finding finding) => newRules.contains(finding.code)),
      isEmpty,
    );
  });

  test('checks RegExp allocation only where a loop repeats evaluation', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/loop_regex.dart': sourceFixture(
        'dart/checks_regexp_allocation_only_where_a_loop_repeats_evaluation/loop_regex.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-regexp-created-in-loop',
      ),
      hasLength(1),
    );
  });

  test('finds public contract Flutter parent and membership risks', () {
    final List<Finding> risky = DartRuleAnalysis().findings(<String, String>{
      'lib/contracts.dart': sourceFixture(
        'dart/finds_public_contract_flutter_parent_and_membership_risks/contracts.dart',
      ),
    });
    expect(
      risky.map((Finding finding) => finding.code).toSet(),
      containsAll(<String>{
        'dart-copy-with-missing-field',
        'dart-enum-name-persistence',
        'dart-late-final-persistence',
        'dart-map-string-dynamic-boundary',
        'dart-quadratic-list-membership',
        'flutter-expanded-outside-flex',
        'flutter-image-network-no-error-builder',
        'flutter-provider-watch-in-callback',
      }),
    );

    final List<Finding> safe = DartRuleAnalysis().findings(<String, String>{
      'lib/contracts_safe.dart': sourceFixture(
        'dart/finds_public_contract_flutter_parent_and_membership_risks/contracts_safe.dart',
      ),
    });
    const Set<String> newRules = <String>{
      'dart-copy-with-missing-field',
      'dart-enum-name-persistence',
      'dart-late-final-persistence',
      'dart-map-string-dynamic-boundary',
      'dart-quadratic-list-membership',
      'flutter-expanded-outside-flex',
      'flutter-image-network-no-error-builder',
      'flutter-provider-watch-in-callback',
    };
    expect(
      safe.where((Finding finding) => newRules.contains(finding.code)),
      isEmpty,
    );
  });

  test('distinguishes model name fields from persisted enum names', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/search_history.dart': sourceFixture(
        'dart/distinguishes_model_name_fields_from_persisted_enum_names/search_history.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-enum-name-persistence',
      ),
      isEmpty,
    );
  });

  test('ignores method-local late finals in persistent classes', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/local_late.dart': sourceFixture(
        'dart/ignores_method_local_late_finals_in_persistent_classes/local_late.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-late-final-persistence',
      ),
      isEmpty,
    );
  });

  test('allows Expanded passed to a custom widget factory', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/custom_tile.dart': sourceFixture(
        'dart/allows_expanded_passed_to_a_custom_widget_factory/custom_tile.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'flutter-expanded-outside-flex',
      ),
      isEmpty,
    );
  });

  test('ignores loose Dart sources outside a package', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-loose-dart-source-',
    );
    addTearDown(() => root.deleteSync(recursive: true));

    final Iterable<Finding> findings = DartRuleAnalysis()
        .findings(<String, String>{
          'main.dart': 'void main() {}',
        }, config: AnalysisConfig(root: root.path))
        .where(
          (Finding finding) => finding.code == 'dart-recommended-lints-missing',
        );

    expect(findings, isEmpty);
  });

  test('requires analyzer configuration for a recognized Dart package', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-dart-package-lints-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');

    final Finding finding = DartRuleAnalysis()
        .findings(<String, String>{
          'lib/main.dart': 'void main() {}',
        }, config: AnalysisConfig(root: root.path))
        .singleWhere(
          (Finding item) => item.code == 'dart-recommended-lints-missing',
        );

    expect(finding.path, 'analysis_options.yaml');
    expect(finding.message, 'analysis_options.yaml is missing');
  });

  test('reports missing analyzer coverage once per project', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-dart-lints-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    File(
      '${root.path}/analysis_options.yaml',
    ).writeAsStringSync('include: package:lints/recommended.yaml\n');

    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/main.dart': 'void main() {}',
    }, config: AnalysisConfig(root: root.path));

    final Finding finding = findings.singleWhere(
      (Finding item) => item.code == 'dart-recommended-lints-missing',
    );
    expect(finding.message, contains('cancel_subscriptions'));
    expect(finding.message, contains('use_build_context_synchronously'));
    expect(finding.message, isNot(contains('implementation_imports')));
  });

  test(
    'does not require analyzer configuration for embedded test fixtures',
    () {
      final Directory root = Directory.systemTemp.createTempSync(
        'cb-dart-fixtures-',
      );
      addTearDown(() => root.deleteSync(recursive: true));

      final Iterable<Finding> findings = DartRuleAnalysis()
          .findings(<String, String>{
            '__tests__/fixtures/kernel-parity/torture.dart': 'void run() {}',
          }, config: AnalysisConfig(root: root.path))
          .where(
            (Finding finding) =>
                finding.code == 'dart-recommended-lints-missing',
          );

      expect(findings, isEmpty);
    },
  );

  test('checks analyzer coverage at a nested Dart package root', () {
    final Directory root = Directory.systemTemp.createTempSync(
      'cb-nested-dart-lints-',
    );
    addTearDown(() => root.deleteSync(recursive: true));
    Directory('${root.path}/app/lib').createSync(recursive: true);
    File('${root.path}/app/pubspec.yaml').writeAsStringSync('name: app\n');
    File(
      '${root.path}/app/analysis_options.yaml',
    ).writeAsStringSync('include: package:flutter_lints/flutter.yaml\n');

    final Finding finding = DartRuleAnalysis()
        .findings(<String, String>{
          'app/lib/main.dart': 'void main() {}',
        }, config: AnalysisConfig(root: root.path))
        .singleWhere(
          (Finding item) => item.code == 'dart-recommended-lints-missing',
        );

    expect(finding.path, 'app/analysis_options.yaml');
    expect(finding.message, contains('cancel_subscriptions'));
  });
  test('accepts copyWith methods that explicitly preserve unselected fields', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/model.dart': sourceFixture(
        'dart/accepts_copywith_methods_that_explicitly_preserve_unselected_fields/model.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-copy-with-missing-field',
      ),
      isEmpty,
    );
  });

  test('accepts copyWith fields preserved on a newly constructed cascade', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/render_context.dart': sourceFixture(
        'dart/accepts_copywith_fields_preserved_on_a_newly_constructed_cascade/render_context.dart',
      ),
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-copy-with-missing-field',
      ),
      isEmpty,
    );
  });

  test('reports copyWith fields cascaded onto a different object', () {
    final List<Finding> findings = DartRuleAnalysis().findings(<String, String>{
      'lib/model.dart': sourceFixture(
        'dart/reports_copywith_fields_cascaded_onto_a_different_object/model.dart',
      ),
    });

    final Finding finding = findings.singleWhere(
      (Finding finding) => finding.code == 'dart-copy-with-missing-field',
    );
    expect(finding.message, contains('recursion'));
  });

  test('reports strongly overlapping data models only in semantic mode', () {
    final Map<String, String> sources = <String, String>{
      'lib/user_profile.dart': sourceFixture(
        'dart/reports_strongly_overlapping_data_models_only_in_semantic_mode/user_profile.dart',
      ),
      'lib/account_details.dart': sourceFixture(
        'dart/reports_strongly_overlapping_data_models_only_in_semantic_mode/account_details.dart',
      ),
      'lib/user_summary.dart': sourceFixture(
        'dart/reports_strongly_overlapping_data_models_only_in_semantic_mode/user_summary.dart',
      ),
    };

    final List<Finding> semantic = DartRuleAnalysis().findings(
      sources,
      config: const AnalysisConfig(
        root: '.',
        duplicationMode: DuplicationMode.semantic,
      ),
    );
    final List<Finding> exact = DartRuleAnalysis().findings(
      sources,
      config: const AnalysisConfig(root: '.'),
    );

    final Finding overlap = semantic.singleWhere(
      (Finding finding) => finding.code == 'dart-overlapping-data-model',
    );
    expect(overlap.path, 'lib/account_details.dart');
    expect(overlap.endLine, overlap.line);
    expect(overlap.relatedFiles, <String>['lib/user_profile.dart:1']);
    expect(overlap.snippet, contains('avatarUrl, email, id, name'));
    expect(
      exact.where(
        (Finding finding) => finding.code == 'dart-overlapping-data-model',
      ),
      isEmpty,
    );
  });

  test('ignores inheritance and models below the overlap threshold', () {
    final Map<String, String> sources = <String, String>{
      'lib/base.dart': sourceFixture(
        'dart/ignores_inheritance_and_models_below_the_overlap_threshold/base.dart',
      ),
      'lib/derived.dart': sourceFixture(
        'dart/ignores_inheritance_and_models_below_the_overlap_threshold/derived.dart',
      ),
      'lib/unrelated.dart': sourceFixture(
        'dart/ignores_inheritance_and_models_below_the_overlap_threshold/unrelated.dart',
      ),
    };

    final List<Finding> findings = DartRuleAnalysis().findings(
      sources,
      config: const AnalysisConfig(
        root: '.',
        duplicationMode: DuplicationMode.semantic,
      ),
    );

    expect(
      findings.where(
        (Finding finding) => finding.code == 'dart-overlapping-data-model',
      ),
      isEmpty,
    );
  });
}
