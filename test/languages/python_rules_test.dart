import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final AnalysisConfig config = AnalysisConfig(
    root: '.',
    severityOverrides: <String, RuleSeverity>{
      for (final RuleMetadata rule in RuleCatalog.all.where(
        (RuleMetadata rule) => rule.id.startsWith('py-'),
      ))
        rule.id: rule.defaultSeverity,
    },
  );

  test('emits Python convention, correctness, async, and security rules', () {
    final Iterable<String> codes = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'app.py': sourceFixture(
            'python/emits_python_convention_correctness_async_and_security_rules/app.py',
          ),
        }, config)
        .findings
        .map((Finding item) => item.code);

    expect(
      codes,
      containsAll(<String>[
        'py-multiple-imports',
        'py-eval-exec',
        'py-wildcard-import',
        'py-import-not-top',
        'py-function-naming',
        'py-mutable-default',
        'py-assert-runtime',
        'py-requests-timeout',
        'py-async-blocking-call',
        'py-hardcoded-secret',
        'py-yaml-load',
        'py-sql-string-build',
        'py-open-no-encoding',
        'py-tempfile-mktemp',
      ]),
    );
    expect(config.severityOverrides, hasLength(24));
  });

  test('ignores multiline imports, string spacing, and secret lookups', () {
    final Set<String> codes = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'config.py': sourceFixture(
            'python/ignores_multiline_imports_string_spacing_and_secret_lookups/config.py',
          ),
        }, config)
        .findings
        .map((Finding finding) => finding.code)
        .toSet();

    expect(codes, isNot(contains('py-import-not-top')));
    expect(codes, isNot(contains('py-extraneous-whitespace')));
    expect(codes, isNot(contains('py-open-no-encoding')));
    expect(codes, isNot(contains('py-hardcoded-secret')));
  });

  test('py-eval-exec only flags dynamic execution builtins', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'model.py': sourceFixture(
            'python/py_eval_exec_only_flags_dynamic_execution_builtins/model.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-eval-exec')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[7, 8, 9]),
    );
  });

  test('py-pickle ignores serialization-only use', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'cache.py': sourceFixture(
            'python/py_pickle_ignores_serialization_only_use/cache.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-pickle')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[4, 5]),
    );
  });
  test('py-hardcoded-secret distinguishes credentials from schema names', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'config.py': sourceFixture(
            'python/py_hardcoded_secret_distinguishes_credentials_from_schema_names/config.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-hardcoded-secret')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[1, 2, 3]),
    );
  });

  test('py-hardcoded-secret ignores empty credential initialization', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'config.py': '''self.api_key = ""
settings = {"client_secret": "   "}
token = "credential"
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-hardcoded-secret')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('py-hardcoded-secret ignores documentation and test placeholders', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'example.py': '''client(api_key="your-api-key")
client(api_key="fc-YOUR_API-KEY")
client(api_key="replace-me")
''',
          'tests/test_client.py': '''client(api_key="test")
client(api_key="test-api-key")
client(api_key="fc-test")
''',
          'config.py': '''password = "test"
api_key = "sk-live-1234567890"
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-hardcoded-secret')
        .toList();

    expect(
      findings.map((Finding finding) => (finding.path, finding.line)),
      <(String, int)>[('config.py', 1), ('config.py', 2)],
    );
  });

  test('py-sql-string-build requires an interpolated SQL statement', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'queries.py': sourceFixture(
            'python/py_sql_string_build_requires_an_interpolated_sql_statement/queries.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-sql-string-build')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[1, 2]),
    );
  });

  test('py-sql-string-build keeps SQL evidence in one string expression', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'monitor.py': sourceFixture(
            'python/py_sql_string_build_keeps_sql_evidence_in_one_string_expression/monitor.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-sql-string-build')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4, 5, 6]);
  });

  test('py-sql-string-build ignores SQL syntax inside static literals', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'queries.py':
              '''cursor.execute("SELECT id FROM jobs WHERE id = %s", (job_id,))
cursor.execute("UPDATE jobs SET attempts = attempts + 1")
query = "SELECT * FROM " + table_name
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-sql-string-build')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[3]);
  });

  test('py-compound-statement ignores comments and continued strings', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'generator.py': sourceFixture(
            'python/py_compound_statement_ignores_comments_and_continued_strings/generator.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-compound-statement')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[1, 2]),
    );
  });

  test('py-requests-timeout scans the complete call', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'client.py': sourceFixture(
            'python/py_requests_timeout_scans_the_complete_call/client.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-requests-timeout')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('py-yaml-load accepts a safe ruamel loader', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'config.py': sourceFixture(
            'python/py_yaml_load_accepts_a_safe_ruamel_loader/config.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-yaml-load')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[5]);
  });

  test('ignores asserts that are part of test modules', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'lib/runtime.py': 'assert connection.is_ready\\n',
          'tests/http/test_auth.py': 'assert response.status == 401\\n',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-assert-runtime')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'lib/runtime.py');
  });

  test('recognizes exact __tests__ segments for asserts and test secrets', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'src/__tests__/auth.py': '''assert response.ok
client(api_key="test-api-key")
''',
          'src/__tests__helpers/auth.py': '''assert response.ok
client(api_key="test-api-key")
''',
        }, config)
        .findings
        .where(
          (Finding finding) =>
              finding.code == 'py-assert-runtime' ||
              finding.code == 'py-hardcoded-secret',
        )
        .toList();

    expect(
      findings.map((Finding finding) => (finding.path, finding.line)),
      <(String, int)>[
        ('src/__tests__helpers/auth.py', 1),
        ('src/__tests__helpers/auth.py', 2),
      ],
    );
  });

  test('distinguishes enabling debug from recording debug state', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'config.py': '''debug = True
self.curl_is_debug = True
app.run(debug=True)
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-debug-enabled')
        .toList();

    expect(
      findings.map((Finding finding) => finding.line),
      orderedEquals(<int>[1, 3]),
    );
  });

  test('ignores repeated single-character credential test fillers', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'auth.py': '''password = "actual credential"
password = "x" * 65535
password = 'x' * (47 * 1024)
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-hardcoded-secret')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 1);
  });

  test('accepts explicit stderr and terminating CLI exception handlers', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'validate.py': sourceFixture(
            'python/accepts_explicit_stderr_and_terminating_cli_exception_handlers/validate.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-logging-exception')
        .toList();

    expect(findings, hasLength(1));
  });

  test('module docstrings do not make following imports late', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'client.py': sourceFixture(
            'python/module_docstrings_do_not_make_following_imports_late/client.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-import-not-top')
        .toList();

    expect(findings, isEmpty);
  });

  test('shebang and module docstring keep imports at module top', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'generate.py': sourceFixture(
            'python/shebang_and_module_docstring_keep_imports_at_module_top/generate.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-import-not-top')
        .toList();

    expect(findings, isEmpty);
  });

  test('allows imports scoped to conditional platform blocks', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'platform.py': sourceFixture(
            'python/allows_imports_scoped_to_conditional_platform_blocks/platform.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-import-not-top')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 9);
  });

  test('ignores rule-like text in prefixed and function docstrings', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('python').analyze(<
      String,
      String
    >{
      'runner.py': sourceFixture(
        'python/ignores_rule_like_text_in_prefixed_and_function_docstrings/runner.py',
      ),
    }, config).findings;

    expect(
      findings
          .where((Finding finding) => finding.code == 'py-subprocess-shell')
          .map((Finding finding) => finding.line),
      <int>[11],
    );
    final Iterable<String> codes = findings.map(
      (Finding finding) => finding.code,
    );
    expect(codes, isNot(contains('py-import-not-top')));
    expect(codes, isNot(contains('py-compound-statement')));
    expect(codes, isNot(contains('py-extraneous-whitespace')));
  });

  test('ignores text opens that are expected to fail before decoding', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'files_test.py': sourceFixture(
            'python/ignores_text_opens_that_are_expected_to_fail_before_decoding/files_test.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-open-no-encoding')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });
  test('py-extraneous-whitespace accepts multidimensional slices', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'tensor.py': sourceFixture(
            'python/py_extraneous_whitespace_accepts_multidimensional_slices/tensor.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-extraneous-whitespace')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });

  test('py-backslash-continuation ignores multiline string openers', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'format.py': sourceFixture(
            'python/py_backslash_continuation_ignores_multiline_string_openers/format.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-backslash-continuation')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });

  test('accepts standard HTTP request handler method names', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'server.py': sourceFixture(
            'python/accepts_standard_http_request_handler_method_names/server.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-function-naming')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('accepts unittest lifecycle method names', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'tests/base.py': sourceFixture(
            'python/accepts_unittest_lifecycle_method_names/base.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-function-naming')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[8]);
  });

  test('accepts declared comtypes interface callbacks only', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'events.py': sourceFixture(
            'python/accepts_declared_comtypes_interface_callbacks_only/events.py',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-function-naming')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 8);
  });
  test('ignores prose and comments that resemble Python findings', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'policy.py': sourceFixture(
            'python/ignores_prose_and_comments_that_resemble_python_findings/policy.py',
          ),
        }, config)
        .findings
        .where(
          (Finding finding) =>
              finding.code == 'py-compound-statement' ||
              finding.code == 'py-open-no-encoding',
        )
        .toList();

    expect(
      findings.map((Finding finding) => (finding.code, finding.line)),
      <(String, int)>[
        ('py-compound-statement', 12),
        ('py-open-no-encoding', 13),
      ],
    );
  });

  test('ignores credential and SQL vocabulary in educational fixtures', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'fixtures.py': sourceFixture(
            'python/ignores_credential_and_sql_vocabulary_in_educational_fixtures/fixtures.py',
          ),
        }, config)
        .findings
        .where(
          (Finding finding) =>
              finding.code == 'py-hardcoded-secret' ||
              finding.code == 'py-sql-string-build',
        )
        .toList();

    expect(
      findings.map((Finding finding) => (finding.code, finding.line)),
      <(String, int)>[('py-hardcoded-secret', 6), ('py-sql-string-build', 7)],
    );
  });

  test('py-compound-statement accepts loop headers with inline comments', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('python')
        .analyze(<String, String>{
          'ring.py': '''for replica in range(num_replicas):  # virtual nodes
    add(replica)
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'py-compound-statement')
        .toList();

    expect(findings, isEmpty);
  });
}
