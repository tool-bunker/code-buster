import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  AnalysisConfig configFor(String prefix) => AnalysisConfig(
    root: '.',
    severityOverrides: <String, RuleSeverity>{
      for (final RuleMetadata rule in RuleCatalog.all.where(
        (RuleMetadata rule) => rule.id.startsWith(prefix),
      ))
        rule.id: rule.defaultSeverity,
    },
  );

  test('emits Lua safety and hot-loop findings', () {
    final Iterable<String> codes = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(<String, String>{
          'main.lua': sourceFixture(
            'lua-javascript/emits_lua_safety_and_hot_loop_findings/main.lua',
          ),
        }, configFor('lua-'))
        .findings
        .map((Finding item) => item.code);
    expect(
      codes,
      containsAll(<String>[
        'lua-global-assignment',
        'lua-print-in-loop',
        'lua-table-alloc-in-loop',
        'lua-os-execute',
        'lua-loadstring',
      ]),
    );
  });

  test(
    'Lua global assignment ignores function-call table fields and lexical locals',
    () {
      final List<Finding> findings = LanguagePluginRegistry.standard()
          .require('lua')
          .analyze(<String, String>{
            'main.lua': sourceFixture(
              'lua-javascript/lua_global_assignment_ignores_function_call_table_fields_and_lexical_l/main.lua',
            ),
          }, configFor('lua-'))
          .findings
          .where((Finding finding) => finding.code == 'lua-global-assignment')
          .toList();

      expect(findings, hasLength(1));
      expect(findings.single.line, 24);
    },
  );

  test('Lua loadstring reports only bare unshadowed dynamic-load calls', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(<String, String>{
          'positives.lua': sourceFixture(
            'lua-javascript/lua_loadstring_reports_only_bare_unshadowed_dynamic_load_calls/positives.lua',
          ),
          'negatives.lua': sourceFixture(
            'lua-javascript/lua_loadstring_reports_only_bare_unshadowed_dynamic_load_calls/negatives.lua',
          ),
          'long_brackets.lua': sourceFixture(
            'lua-javascript/lua_loadstring_reports_only_bare_unshadowed_dynamic_load_calls/long_brackets.lua',
          ),
        }, configFor('lua-'))
        .findings
        .where((Finding finding) => finding.code == 'lua-loadstring')
        .toList();

    expect(
      findings.map((Finding finding) => (finding.path, finding.line)),
      <(String, int)>[
        ('positives.lua', 1),
        ('positives.lua', 2),
        ('positives.lua', 3),
        ('long_brackets.lua', 11),
        ('long_brackets.lua', 12),
        ('long_brackets.lua', 14),
        ('long_brackets.lua', 15),
      ],
    );
  });

  test('Lua pair mutation requires the iterated table to be mutated', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(<String, String>{
          'main.lua': sourceFixture(
            'lua-javascript/lua_pair_mutation_requires_the_iterated_table_to_be_mutated/main.lua',
          ),
        }, configFor('lua-'))
        .findings
        .where((Finding finding) => finding.code == 'lua-mutate-pairs')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[9, 12, 15]);
  });

  test('does not treat drawing or update helpers as hot callbacks', () {
    final Iterable<Finding>
    findings = LanguagePluginRegistry.standard().require('lua').analyze(<
      String,
      String
    >{
      'tools.lua': sourceFixture(
        'lua-javascript/does_not_treat_drawing_or_update_helpers_as_hot_callbacks/tools.lua',
      ),
    }, configFor('lua-')).findings;

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'lua-print-in-loop' ||
            finding.code == 'lua-table-alloc-in-loop',
      ),
      isEmpty,
    );
  });

  test('limits Lua hot findings to the current update or draw function', () {
    final List<(String, int)> findings = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(<String, String>{
          'callbacks.lua': sourceFixture(
            'lua-javascript/limits_lua_hot_findings_to_the_current_update_or_draw_function/callbacks.lua',
          ),
        }, configFor('lua-'))
        .findings
        .where(
          (Finding finding) =>
              finding.code == 'lua-print-in-loop' ||
              finding.code == 'lua-table-alloc-in-loop',
        )
        .map((Finding finding) => (finding.code, finding.line))
        .toList();

    expect(findings, <(String, int)>[
      ('lua-print-in-loop', 11),
      ('lua-print-in-loop', 21),
      ('lua-table-alloc-in-loop', 12),
      ('lua-table-alloc-in-loop', 22),
    ]);
  });

  test('tracks Lua hot-function scope and ignores Luau type literals', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('lua')
        .analyze(<String, String>{
          'main.luau': sourceFixture(
            'lua-javascript/tracks_lua_hot_function_scope_and_ignores_luau_type_literals/main.luau',
          ),
        }, configFor('lua-'))
        .findings
        .where((Finding finding) => finding.code == 'lua-table-alloc-in-loop')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('emits TypeScript correctness and security findings', () {
    final Iterable<String> codes = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'main.ts': sourceFixture(
            'lua-javascript/emits_typescript_correctness_and_security_findings/main.ts',
          ),
        }, configFor('ts-'))
        .findings
        .map((Finding item) => item.code);
    expect(
      codes,
      containsAll(<String>[
        'ts-any',
        'ts-json-parse-unsafe',
        'ts-console',
        'ts-debugger',
        'ts-eval',
        'ts-inner-html',
        'ts-floating-promise',
        'ts-hardcoded-secret',
      ]),
    );
  });

  test('ts-eval reports direct globals but ignores members and declarations', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'retrieval.ts': sourceFixture(
            'lua-javascript/ts_eval_reports_direct_globals_but_ignores_members_and_declarations/retrieval.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-eval')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3, 4, 5]);
  });

  test('accepts JSON embedded in a dedicated document element', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'search.js': sourceFixture(
            'lua-javascript/accepts_json_embedded_in_a_dedicated_document_element/search.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-json-parse-unsafe')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[1]);
  });

  test('accepts JSON stringify round trips', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'clone.js': sourceFixture(
            'lua-javascript/accepts_json_stringify_round_trips/clone.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-json-parse-unsafe')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });
  test('accepts JSON parsing only inside handled try blocks', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'parse.js': sourceFixture(
            'lua-javascript/accepts_json_parsing_only_inside_handled_try_blocks/parse.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-json-parse-unsafe')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[
      9,
      12,
      17,
      19,
    ]);
  });

  test('reports only dynamic innerHTML writes', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'copy-button.js': sourceFixture(
            'lua-javascript/reports_only_dynamic_innerhtml_writes/copy-button.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-inner-html')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[
      12,
      13,
      14,
      15,
      16,
      17,
      20,
    ]);
  });

  test('accepts only completely static innerHTML expressions', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'status.js': sourceFixture(
            'lua-javascript/accepts_only_completely_static_innerhtml_expressions/status.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-inner-html')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[6, 10]);
  });

  test('ignores innerHTML names in string text but scans interpolations', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'prompt.tsx': sourceFixture(
            'lua-javascript/ignores_innerhtml_names_in_string_text_but_scans_interpolations/source.txt',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-inner-html')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5]);
  });

  test('ignores scripting-looking text in multiline template literals', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('javascript').analyze(<
      String,
      String
    >{
      'examples.js': sourceFixture(
        'lua-javascript/ignores_scripting_looking_text_in_multiline_template_literals/examples.js',
      ),
    }, configFor('ts-')).findings;

    expect(
      findings
          .where((Finding finding) => finding.code == 'ts-console')
          .map((Finding finding) => finding.line),
      <int>[5],
    );
    expect(
      findings.where(
        (Finding finding) => finding.code == 'ts-floating-promise',
      ),
      isEmpty,
    );
  });

  test('reports await only in an open loop in the same function', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'worker.ts': sourceFixture(
            'lua-javascript/reports_await_only_in_an_open_loop_in_the_same_function/worker.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-await-in-loop')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[17]);
  });

  test('does not carry loop state into an adjacent class method', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'adapter.ts': sourceFixture(
            'lua-javascript/does_not_carry_loop_state_into_an_adjacent_class_method/adapter.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-await-in-loop')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('does not treat credential-shaped property access as a secret', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('javascript').analyze(<
      String,
      String
    >{
      'auth.js': sourceFixture(
        'lua-javascript/does_not_treat_credential_shaped_property_access_as_a_secret/auth.js',
      ),
    }, configFor('ts-')).findings;

    expect(
      findings.where(
        (Finding finding) => finding.code == 'ts-hardcoded-secret',
      ),
      hasLength(1),
    );
  });

  test('does not treat a URL query interpolation as a hardcoded secret', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'oidc-client.js': '''
let id_token_url = getIDTokenUrl();
id_token_url = `\${id_token_url}&audience=\${encodedAudience}`;
const api_token = "literal-token";
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('does not treat date-format token loops as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'moment.js': sourceFixture(
            'lua-javascript/does_not_treat_date_format_token_loops_as_hardcoded_secrets/moment.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });

  test('does not treat enum identifiers as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'routes.ts': sourceFixture(
            'lua-javascript/does_not_treat_enum_identifiers_as_hardcoded_secrets/routes.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[6]);
  });

  test('does not treat HTML attributes in templates as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'login-page.ts': '''
const nonce = request.nonce;
const page = `<style nonce="\${nonce}">body { color: black; }</style>`;
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings, isEmpty);
  });

  test('does not scan source examples inside multiline template literals', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'token-example.js': sourceFixture(
            'lua-javascript/does_not_scan_source_examples_inside_multiline_template_literals/token-example.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('does not treat empty credential variables as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'password-generator.js': '''
let generatedPassword = '';
const apiSecret = "   ";
const password = "literal-secret";
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('does not treat explicit empty sentinels as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'compiler.ts': '''
export const emptySlotScopeToken = `_empty_`;
const token = "literal-token";
const nonce = "4AEemGb0xJptoIGFP3Nd";
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[2, 3]);
  });

  test('does not treat computed template credentials as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'auth.ts': sourceFixture(
            'lua-javascript/does_not_treat_computed_template_credentials_as_hardcoded_secrets/auth.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5]);
  });

  test('does not treat a generated secret prefix as a hardcoded secret', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'webhook.ts': '''
const bytes = crypto.getRandomValues(new Uint8Array(32));
const secret = "whsec_" + btoa(String.fromCharCode(...bytes));
const apiSecret = "literal-secret";
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('does not treat generated repeated values as hardcoded secrets', () {
    final Iterable<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'dev-control.test.mjs': '''
const token = 'ab'.repeat(32);
const apiToken = 'literal-token';
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-hardcoded-secret');

    expect(findings.map((Finding finding) => finding.line), <int>[2]);
  });

  test('accepts a multiline handled promise chain', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'download.js': sourceFixture(
            'lua-javascript/accepts_a_multiline_handled_promise_chain/download.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[7]);
  });

  test('does not assume methods on a generic client return promises', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'client.ts': sourceFixture(
            'lua-javascript/does_not_assume_methods_on_a_generic_client_return_promises/client.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings, isEmpty);
  });

  test('requires a promise call and ignores synchronous bind calls', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'client.ts': sourceFixture(
            'lua-javascript/requires_a_promise_call_and_ignores_synchronous_bind_calls/client.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[6, 7]);
  });

  test('accepts promise calls nested in an awaited wrapper', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'batch.ts': sourceFixture(
            'lua-javascript/accepts_promise_calls_nested_in_an_awaited_wrapper/batch.ts',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('does not assume methods on a generic api object return promises', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'editor.ts': '''
api.dispatch(api.actions.updateContent("draft"));
api.discardDraft();
fetch("/draft");
''',
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('accepts a promise passed to a Service Worker lifetime method', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('javascript')
        .analyze(<String, String>{
          'service-worker.js': sourceFixture(
            'lua-javascript/accepts_a_promise_passed_to_a_service_worker_lifetime_method/service-worker.js',
          ),
        }, configFor('ts-'))
        .findings
        .where((Finding finding) => finding.code == 'ts-floating-promise')
        .toList();

    expect(findings, isEmpty);
  });
}
