import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/sql/sql_analysis.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  test('finds complete PostgreSQL and migration hazards', () {
    final List<Finding> findings = SqlRuleAnalysis().findings(<String, String>{
      'migration.sql': sourceFixture(
        'sql/finds_complete_postgresql_and_migration_hazards/migration.sql',
      ),
    }, checkNonConcurrentIndexes: true);
    expect(
      findings.map((Finding item) => item.code),
      containsAll(<String>[
        'sql-select-star',
        'sql-leading-wildcard-like',
        'sql-delete-without-where',
        'sql-update-without-where',
        'sql-drop-table-without-if-exists',
        'sql-create-index-nonconcurrent',
        'sql-add-not-null-default',
      ]),
    );
  });

  test('does not treat an INSERT conflict action as an unbounded UPDATE', () {
    final List<Finding> findings = SqlRuleAnalysis().findings(<String, String>{
      'migration.sql': '''INSERT INTO versions (name, value)
VALUES ('schema', 1)
ON CONFLICT (name) DO UPDATE SET value = 1;
''',
    });

    expect(
      findings.where(
        (Finding finding) => finding.code == 'sql-update-without-where',
      ),
      isEmpty,
    );
  });

  test('does not recommend PostgreSQL index syntax for SQLite schemas', () {
    final Iterable<Finding> findings = SqlRuleAnalysis()
        .findings(<String, String>{
          'schema.sql': '''
-- Application SQLite Schema
CREATE INDEX idx_users_name ON users(name);
''',
        }, checkNonConcurrentIndexes: true)
        .where(
          (Finding finding) => finding.code == 'sql-create-index-nonconcurrent',
        );

    expect(findings, isEmpty);
  });

  test('recognizes SQLite AUTOINCREMENT before checking index syntax', () {
    final Iterable<Finding> findings = SqlRuleAnalysis()
        .findings(<String, String>{
          'schema.sql': sourceFixture(
            'sql/recognizes_sqlite_autoincrement_before_checking_index_syntax/schema.sql',
          ),
        }, checkNonConcurrentIndexes: true)
        .where(
          (Finding finding) => finding.code == 'sql-create-index-nonconcurrent',
        );

    expect(findings, isEmpty);
  });

  test('recommends concurrent indexes only for PostgreSQL-like SQL', () {
    final Iterable<Finding> findings = SqlRuleAnalysis()
        .findings(<String, String>{
          'postgres.sql': 'CREATE INDEX idx_pg ON users(name);',
          'unknown.sql': 'CREATE INDEX idx_unknown ON users(name);',
          'mysql.sql': '''
CREATE TABLE `users` (`name` varchar(100)) ENGINE=InnoDB;
CREATE INDEX `idx_mysql` ON `users` (`name`);
''',
          'sql-server.sql': sourceFixture(
            'sql/recommends_concurrent_indexes_only_for_postgresql_like_sql/sql-server.sql',
          ),
        }, checkNonConcurrentIndexes: true)
        .where(
          (Finding finding) => finding.code == 'sql-create-index-nonconcurrent',
        );

    expect(findings.map((Finding finding) => finding.path), <String>[
      'postgres.sql',
      'unknown.sql',
    ]);
  });

  test('respects MySQL dialect and catches inline string construction', () {
    expect(
      SqlRuleAnalysis().findings(<String, String>{
        'index.sql': 'CREATE INDEX idx ON users(name);',
      }, dialect: 'mysql'),
      isEmpty,
    );
    expect(
      SqlRuleAnalysis()
          .inlineFindings(<String, String>{
            'query.dart':
                r'''final query = "SELECT name FROM users WHERE id = ${id}";''',
          })
          .single
          .code,
      'sql-inline-string-concat',
    );
    expect(
      SqlRuleAnalysis().inlineFindings(<String, String>{
        'parser.dart':
            "final sql = 'UPDATE x SET value = value + 1 RETURNING *';",
        'prototype.html':
            r'<span>`SELECT * FROM users WHERE id = ${userId}`</span>',
        'disabled.dart':
            r'''/* final sql = "SELECT * FROM users WHERE id = ${id}"; */''',
        'commented.ts':
            r'''// const sql = `DELETE FROM users WHERE id = ${id}`;''',
        'wmi.cs': sourceFixture(
          'sql/respects_mysql_dialect_and_catches_inline_string_construction/wmi.cs',
        ),
        'prompt.cs':
            r'''var question = $"Which team member responds next? (Select only from: {{${names}}}).";''',
      }),
      isEmpty,
    );
  });

  test('requires SQL construction or execution context', () {
    final List<Finding> findings = SqlRuleAnalysis()
        .inlineFindings(<String, String>{
          'db.go': '''
tx.ExecContext(ctx, "DELETE FROM "+table)
return wrap(err, "delete from "+table)
fmt.Errorf("failed to insert into dataset: "+err.Error())
''',
        });

    expect(findings.map((Finding finding) => finding.line), <int>[1]);
  });

  test('accepts parameterized SQL tagged templates', () {
    final List<Finding> findings = SqlRuleAnalysis().inlineFindings(
      <String, String>{
        'rpc.ts':
            r'const rows = sql`select * from users where id = ${userId}`;',
      },
    );

    expect(findings, isEmpty);
  });

  test('accepts generated parameter placeholder lists', () {
    final List<Finding> findings = SqlRuleAnalysis()
        .inlineFindings(<String, String>{
          'queries.ts': sourceFixture(
            'sql/accepts_generated_parameter_placeholder_lists/queries.ts',
          ),
        });

    expect(findings.map((Finding finding) => finding.line), <int>[4]);
  });

  test('accepts compile-time SQL constants and identifier allowlists', () {
    final Iterable<Finding> findings = SqlRuleAnalysis()
        .inlineFindings(<String, String>{
          'rollup.ts': sourceFixture(
            'sql/accepts_compile_time_sql_constants_and_identifier_allowlists/rollup.ts',
          ),
        })
        .where((Finding finding) => finding.code == 'sql-inline-string-concat');

    expect(findings, isEmpty);
  });

  test('accepts EF Core parameterized interpolation only', () {
    final List<Finding> findings = SqlRuleAnalysis()
        .inlineFindings(<String, String>{
          'Queries.cs': sourceFixture(
            'sql/accepts_ef_core_parameterized_interpolation_only/Queries.cs',
          ),
        });

    expect(findings.map((Finding finding) => finding.line), <int>[5, 6]);
  });

  test('accepts provably numeric C# SQL interpolation only', () {
    final List<Finding> findings = SqlRuleAnalysis()
        .inlineFindings(<String, String>{
          'Queries.cs': sourceFixture(
            'sql/accepts_provably_numeric_c_sql_interpolation_only/Queries.cs',
          ),
        });

    expect(findings.map((Finding finding) => finding.line), <int>[7]);
  });

  test('ignores foreign source fixtures embedded in Dart tests', () {
    final List<Finding>
    findings = SqlRuleAnalysis().inlineFindings(<String, String>{
      'adapter_test.dart': sourceFixture(
        'sql/ignores_foreign_source_fixtures_embedded_in_dart_tests/adapter_fixture.dart',
      ),
    });

    expect(findings, isEmpty);
  });

  test('reports the hazardous expression line inside compound statements', () {
    final List<Finding> findings = SqlRuleAnalysis().findings(<String, String>{
      'migration.sql': sourceFixture(
        'sql/reports_the_hazardous_expression_line_inside_compound_statements/migration.sql',
      ),
    });

    expect(
      findings
          .singleWhere(
            (Finding finding) => finding.code == 'sql-add-not-null-default',
          )
          .line,
      4,
    );
  });

  test('ignores migration warnings inside SQL block comments', () {
    final List<Finding> findings = SqlRuleAnalysis().findings(<String, String>{
      'migration.sql': sourceFixture(
        'sql/ignores_migration_warnings_inside_sql_block_comments/migration.sql',
      ),
    });

    expect(
      findings
          .where(
            (Finding finding) => finding.code == 'sql-add-not-null-default',
          )
          .map((Finding finding) => finding.line),
      <int>[7],
    );
  });

  test('catalogues every current SQL rule', () {
    expect(
      RuleCatalog.all.where((RuleMetadata rule) => rule.id.startsWith('sql-')),
      hasLength(10),
    );
  });
}
