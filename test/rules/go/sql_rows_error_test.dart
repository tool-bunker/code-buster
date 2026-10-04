import 'package:code_buster/src/internal.dart';
import 'package:code_buster/src/rules/go/sql_rows_error.dart';
import 'package:test/test.dart';

void main() {
  test('reports SQL row iteration without a terminal error check', () {
    final List<Finding> findings = const GoSqlRowsErrorRule()
        .analyze(
          const RuleContext(
            config: AnalysisConfig(root: '.'),
            sources: <String, String>{
              'users.go': '''
package users

func load(db *sql.DB) error {
  rows, err := db.QueryContext(ctx, query)
  if err != nil { return err }
  defer rows.Close()
  for rows.Next() {
    scan(rows)
  }
  return nil
}
''',
            },
            language: 'go',
          ),
        )
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.code, 'go-sql-rows-error-not-checked');
    expect(findings.single.line, 7);
    expect(findings.single.confidence, 'high');
  });

  test('accepts returned, assigned, and conditionally checked row errors', () {
    final Iterable<Finding> findings = const GoSqlRowsErrorRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{
          'users.go': '''
package users

func returned(db *sql.DB) error {
  rows, err := db.Query(query)
  if err != nil { return err }
  for rows.Next() { scan(rows) }
  return rows.Err()
}

func assigned(db *sql.DB) error {
  items, err := db.QueryContext(ctx, query)
  if err != nil { return err }
  for items.Next() { scan(items) }
  err = items.Err()
  return err
}

func conditional(db *sql.DB) error {
  result, err := db.Query(query)
  if err != nil { return err }
  for result.Next() { scan(result) }
  if err := result.Err(); err != nil { return err }
  return nil
}
''',
        },
        language: 'go',
      ),
    );

    expect(findings, isEmpty);
  });

  test('requires local iteration of a Query result', () {
    final Iterable<Finding> findings = const GoSqlRowsErrorRule().analyze(
      const RuleContext(
        config: AnalysisConfig(root: '.'),
        sources: <String, String>{
          'users.go': '''
package users

func queryOnly(db *sql.DB) (*sql.Rows, error) {
  rows, err := db.Query(query)
  return rows, err
}

func unrelated(stream Stream) {
  for stream.Next() { consume(stream) }
}
''',
        },
        language: 'go',
      ),
    );

    expect(findings, isEmpty);
  });
}
