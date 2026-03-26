// SQL must be split into statements with comments and strings understood before safety rules can inspect clauses reliably.

import '../../core/models.dart';

/// PostgreSQL/MySQL statement checks for standalone SQL files.
final class SqlRuleAnalysis {
  /// Analyzes complete semicolon-delimited statements in [sources].
  List<Finding> findings(
    Map<String, String> sources, {
    String dialect = 'postgres',
    bool checkNonConcurrentIndexes = false,
  }) {
    final List<Finding> result = <Finding>[];
    final bool postgres = dialect.toLowerCase() != 'mysql';
    for (final MapEntry<String, String> entry in sources.entries) {
      final bool entryPostgres =
          postgres && !_isClearlyNonPostgres(entry.key, entry.value);
      final List<String> lines = entry.value.split('\n');
      var statement = '';
      var startLine = 1;
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        final ({String code, bool inBlockComment}) stripped = _stripSqlComments(
          lines[index],
          inBlockComment,
        );
        inBlockComment = stripped.inBlockComment;
        final String text = stripped.code.trim();
        if (text.isEmpty) continue;
        if (statement.isEmpty) startLine = index + 1;
        statement = statement.isEmpty ? text : '$statement\n$text';
        if (text.contains(';')) {
          _check(
            result,
            entry.key,
            startLine,
            statement,
            entryPostgres,
            checkNonConcurrentIndexes,
          );
          statement = '';
        }
      }
      if (statement.isNotEmpty) {
        _check(
          result,
          entry.key,
          startLine,
          statement,
          entryPostgres,
          checkNonConcurrentIndexes,
        );
      }
    }
    return result;
  }

  static ({String code, bool inBlockComment}) _stripSqlComments(
    String line,
    bool inBlockComment,
  ) {
    final StringBuffer code = StringBuffer();
    String? quote;
    var index = 0;
    while (index < line.length) {
      if (inBlockComment) {
        final int close = line.indexOf('*/', index);
        if (close < 0) break;
        index = close + 2;
        inBlockComment = false;
        continue;
      }

      final String character = line[index];
      if (quote != null) {
        code.write(character);
        if (character == quote) {
          if (index + 1 < line.length && line[index + 1] == quote) {
            code.write(quote);
            index += 2;
            continue;
          }
          quote = null;
        }
        index++;
        continue;
      }

      if (character == "'" || character == '"') {
        quote = character;
        code.write(character);
        index++;
        continue;
      }
      if (character == '-' &&
          index + 1 < line.length &&
          line[index + 1] == '-') {
        break;
      }
      if (character == '/' &&
          index + 1 < line.length &&
          line[index + 1] == '*') {
        inBlockComment = true;
        index += 2;
        continue;
      }
      code.write(character);
      index++;
    }
    return (code: code.toString(), inBlockComment: inBlockComment);
  }

  static bool _isClearlyNonPostgres(String path, String source) {
    if (_nonPostgresPath.hasMatch(path)) return true;

    final String header = source.split('\n').take(5).join('\n');
    return _sqliteHeader.hasMatch(header) ||
        _sqliteSyntax.hasMatch(source) ||
        _mysqlSyntax.hasMatch(source) ||
        _sqlServerSyntax.hasMatch(source);
  }

  static final RegExp _nonPostgresPath = RegExp(
    r'(?:^|[\\/])(?:mysql|sqlite|sqlserver|mssql)(?:[\\/]|$)',
    caseSensitive: false,
  );
  static final RegExp _sqliteHeader = RegExp(
    r'^\s*--[^\n]*\bsqlite\b',
    caseSensitive: false,
    multiLine: true,
  );
  static final RegExp _sqliteSyntax = RegExp(
    r'\bAUTOINCREMENT\b',
    caseSensitive: false,
  );
  static final RegExp _mysqlSyntax = RegExp(
    r'\bENGINE\s*=\s*[A-Za-z]|\bCHARACTER\s+SET\s*=?\s*utf8mb4\b|`[^`\r\n]+`',
    caseSensitive: false,
  );
  static final RegExp _sqlServerSyntax = RegExp(
    r'\bOBJECT_ID\s*\(|\bsys\.indexes\b|^\s*GO\s*$',
    caseSensitive: false,
    multiLine: true,
  );

  void _check(
    List<Finding> result,
    String sourcePath,
    int line,
    String statement,
    bool postgres,
    bool checkNonConcurrentIndexes,
  ) {
    final String sql = statement.toLowerCase().replaceAll(RegExp(r'\s+'), ' ');
    void add(
      String id,
      RuleSeverity severity,
      String message, {
      required RegExp locationPattern,
      String confidence = 'medium',
    }) {
      final List<String> statementLines = statement.split('\n');
      final int offset = statementLines.indexWhere(locationPattern.hasMatch);
      final int findingLine = offset < 0 ? line : line + offset;
      result.add(
        Finding(
          code: id,
          severity: severity,
          path: sourcePath,
          line: findingLine,
          endLine: findingLine,
          message: message,
          confidence: confidence,
          why: _why[id]!,
          suggestion: _suggestions[id]!,
        ),
      );
    }

    if (sql.contains('select *')) {
      add(
        'sql-select-star',
        RuleSeverity.info,
        'SQL uses SELECT *',
        locationPattern: RegExp(r'\bselect\s+\*', caseSensitive: false),
        confidence: 'low',
      );
    }
    if (sql.contains('delete from ') && !sql.contains(' where ')) {
      add(
        'sql-delete-without-where',
        RuleSeverity.warn,
        'DELETE has no WHERE clause',
        locationPattern: RegExp(r'\bdelete\s+from\b', caseSensitive: false),
      );
    }
    if (RegExp(r'^update\b').hasMatch(sql) &&
        sql.contains(' set ') &&
        !sql.contains(' where ')) {
      add(
        'sql-update-without-where',
        RuleSeverity.warn,
        'UPDATE has no WHERE clause',
        locationPattern: RegExp(r'^update\b', caseSensitive: false),
      );
    }
    if (sql.contains('drop table') && !sql.contains('if exists')) {
      add(
        'sql-drop-table-without-if-exists',
        RuleSeverity.info,
        'DROP TABLE lacks IF EXISTS',
        confidence: 'low',
        locationPattern: RegExp(r'\bdrop\s+table\b', caseSensitive: false),
      );
    }
    if (sql.contains('not in') && sql.contains('select')) {
      add(
        'sql-not-in-subquery-null-risk',
        RuleSeverity.info,
        'NOT IN subquery can behave unexpectedly with NULLs',
        confidence: 'low',
        locationPattern: RegExp(r'\bnot\s+in\s*\(', caseSensitive: false),
      );
    }
    if (sql.contains(" like '") &&
        sql.contains('%') &&
        !sql.contains('lower(') &&
        !sql.contains('ilike')) {
      add(
        'sql-case-sensitive-like',
        RuleSeverity.info,
        'LIKE search appears case-sensitive',
        confidence: 'low',
        locationPattern: RegExp(r'\blike\s+[\x27"]', caseSensitive: false),
      );
    }
    if (sql.contains(" like '%")) {
      add(
        'sql-leading-wildcard-like',
        RuleSeverity.info,
        'LIKE pattern starts with wildcard',
        confidence: 'low',
        locationPattern: RegExp(r'\blike\s+[\x27"]%', caseSensitive: false),
      );
    }
    if (postgres &&
        checkNonConcurrentIndexes &&
        sql.contains('create index ') &&
        !sql.contains(' concurrently')) {
      add(
        'sql-create-index-nonconcurrent',
        RuleSeverity.info,
        'CREATE INDEX is not CONCURRENTLY',
        confidence: 'low',
        locationPattern: RegExp(r'\bcreate\s+index\b', caseSensitive: false),
      );
    }
    if (sql.contains('alter table ') &&
        sql.contains(' add column ') &&
        sql.contains(' not null') &&
        sql.contains(' default ')) {
      add(
        'sql-add-not-null-default',
        RuleSeverity.warn,
        'ADD COLUMN NOT NULL DEFAULT may rewrite or lock table',
        locationPattern: RegExp(
          r'\balter\s+table\b.*\badd\s+column\b',
          caseSensitive: false,
        ),
      );
    }
  }

  /// Detects SQL assembled through interpolation/concatenation in other languages.
  List<Finding> inlineFindings(Map<String, String> sources) {
    final List<Finding> result = <Finding>[];
    final RegExp statement = RegExp(
      r'\b(?:select\s+.+\s+from\b(?!\s*:)|insert\s+into|update\s+.+\s+set|delete\s+from)\b',
      caseSensitive: false,
    );
    for (final MapEntry<String, String> entry in sources.entries) {
      if (!RegExp(
        r'\.(?:dart|java|kt|kts|cs|js|jsx|mjs|cjs|ts|tsx|py|rb|php|go)$',
        caseSensitive: false,
      ).hasMatch(entry.key)) {
        continue;
      }
      final List<String> lines = _maskEmbeddedSourceFixtures(
        entry.key,
        entry.value,
      ).split('\n');
      var inBlockComment = false;
      for (var index = 0; index < lines.length; index++) {
        var line = lines[index];
        if (inBlockComment) {
          final int end = line.indexOf('*/');
          if (end < 0) continue;
          line = line.substring(end + 2);
          inBlockComment = false;
        }
        while (true) {
          final int start = line.indexOf('/*');
          if (start < 0) break;
          final int end = line.indexOf('*/', start + 2);
          if (end < 0) {
            line = line.substring(0, start);
            inBlockComment = true;
            break;
          }
          line = '${line.substring(0, start)} ${line.substring(end + 2)}';
        }
        final String trimmed = line.trimLeft();
        if (trimmed.startsWith('//') ||
            trimmed.startsWith('#') ||
            trimmed.startsWith('*')) {
          continue;
        }
        if (_isManagementObjectQuery(lines, index)) {
          continue;
        }
        final bool interpolated =
            line.contains(r'${') || RegExp(r'''\$"[^"\n]*\{''').hasMatch(line);
        final bool safeSqlInterpolation =
            interpolated &&
            (_onlySafeSqlInterpolation(line, entry.value) ||
                _onlySafeCSharpNumericInterpolation(line, lines, index));
        final bool efCoreParameterizedInterpolation =
            interpolated && _isEfCoreParameterizedInterpolation(lines, index);
        final bool concatenated = RegExp(
          r'''(?:["'][^"']*(?:select|insert|update|delete)[^"']*["']\s*\+\s*(?!["'])\w|\b\w[\w.()]*\s*\+\s*["'][^"']*(?:select|insert|update|delete))''',
          caseSensitive: false,
        ).hasMatch(line);
        final bool sqlContext = _isSqlConstructionContext(lines, index);
        if (sqlContext &&
            statement.hasMatch(line) &&
            ((interpolated &&
                    !safeSqlInterpolation &&
                    !efCoreParameterizedInterpolation) ||
                concatenated)) {
          result.add(
            Finding(
              code: 'sql-inline-string-concat',
              severity: RuleSeverity.warn,
              path: entry.key,
              line: index + 1,
              endLine: index + 1,
              message:
                  'inline SQL appears dynamically concatenated or interpolated',
              confidence: 'medium',
              why: _why['sql-inline-string-concat']!,
              suggestion: _suggestions['sql-inline-string-concat']!,
            ),
          );
        }
      }
    }
    return result;
  }

  static String _maskEmbeddedSourceFixtures(String sourcePath, String source) {
    if (!sourcePath.toLowerCase().endsWith('.dart')) return source;
    final List<int> masked = source.codeUnits.toList();
    for (final String quote in <String>["'''", '"""']) {
      final RegExp fixture = RegExp(
        '''["'][^"'\\r\\n]+\\.(?:cs|java|kt|kts|js|jsx|mjs|cjs|ts|tsx|py|rb|php|go)["']\\s*:\\s*r?${RegExp.escape(quote)}''',
        caseSensitive: false,
      );
      for (final RegExpMatch opening in fixture.allMatches(source)) {
        final int contentStart = opening.end;
        final int contentEnd = source.indexOf(quote, contentStart);
        if (contentEnd < 0) continue;
        for (var index = contentStart; index < contentEnd; index++) {
          if (masked[index] != 10 && masked[index] != 13) masked[index] = 32;
        }
      }
    }
    return String.fromCharCodes(masked);
  }

  static bool _isSqlConstructionContext(List<String> lines, int index) {
    final String line = lines[index];
    final RegExp execution = RegExp(
      r'\b(?:execute|exec|query|prepare|raw)\w*\s*\(',
      caseSensitive: false,
    );
    if (execution.hasMatch(line)) return true;

    final RegExpMatch? assignment = RegExp(
      r'\b([A-Za-z_$][\w$]*)\s*=',
    ).firstMatch(line);
    if (assignment != null) {
      final String variable = assignment.group(1)!.toLowerCase();
      final bool sqlStorage =
          variable.contains('query') || variable.contains('sql');
      final bool diagnostic =
          variable.contains('error') ||
          variable.contains('message') ||
          variable.contains('label');
      if (sqlStorage && !diagnostic) return true;
    }

    if (index == 0 || !RegExp(r'''^\s*(?:["'`]|\$")''').hasMatch(line)) {
      return false;
    }
    return execution.hasMatch(lines[index - 1]);
  }

  static bool _isManagementObjectQuery(List<String> lines, int index) {
    final String line = lines[index];
    final RegExp searcherCall = RegExp(r'\bManagementObjectSearcher\s*\(');
    if (searcherCall.hasMatch(line) ||
        (index > 0 && searcherCall.hasMatch(lines[index - 1]))) {
      return true;
    }

    final RegExpMatch? assignment = RegExp(
      r'\b([A-Za-z_]\w*)\s*=',
    ).firstMatch(line);
    if (assignment == null) return false;

    final String variable = assignment.group(1)!;
    final RegExp variableReference = RegExp(
      r'\b' + RegExp.escape(variable) + r'\b',
    );
    final RegExp variableAssignment = RegExp(
      r'\b' + RegExp.escape(variable) + r'\s*=',
    );
    for (var next = index + 1; next < lines.length; next++) {
      final String candidate = lines[next];
      if (!candidate.trimLeft().startsWith('//') &&
          searcherCall.hasMatch(candidate) &&
          variableReference.hasMatch(candidate)) {
        return true;
      }
      if (variableAssignment.hasMatch(candidate)) return false;
    }
    return false;
  }

  static bool _onlySafeSqlInterpolation(String line, String source) {
    final List<RegExpMatch> expressions = RegExp(
      r'\$\{([^}]*)\}',
    ).allMatches(line).toList(growable: false);
    if (expressions.isEmpty) return false;
    for (final RegExpMatch match in expressions) {
      final String expression = match.group(1)!.trim();
      if (_parameterPlaceholderFactory.hasMatch(expression)) continue;
      if (!RegExp(r'^[A-Za-z_$][\w$]*$').hasMatch(expression)) return false;
      if (_isStaticNumericConstant(expression, source) ||
          _isAllowlistedSqlIdentifier(expression, source)) {
        continue;
      }
      final RegExpMatch? declaration = RegExp(
        '\\b(?:const|let|var)\\s+${RegExp.escape(expression)}\\s*=\\s*([^;\\n]+)',
      ).firstMatch(source);
      if (declaration == null ||
          !_parameterPlaceholderFactory.hasMatch(
            declaration.group(1)!.trim(),
          )) {
        return false;
      }
    }
    return true;
  }

  static bool _onlySafeCSharpNumericInterpolation(
    String line,
    List<String> lines,
    int index,
  ) {
    if (!RegExp(r'''\$@?"|@\$"''').hasMatch(line)) return false;
    final List<RegExpMatch> expressions = RegExp(
      r'(?<!\{)\{([^{}]+)\}(?!\})',
    ).allMatches(line).toList(growable: false);
    if (expressions.isEmpty) return false;

    return expressions.every((RegExpMatch match) {
      final String expression = match.group(1)!.trim();
      if (RegExp(
        r'^\((?:s?byte|u?short|u?int|u?long|float|double|decimal)\)\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$',
      ).hasMatch(expression)) {
        return true;
      }
      if (!RegExp(r'^[A-Za-z_]\w*$').hasMatch(expression)) return false;

      final int first = index > 80 ? index - 80 : 0;
      for (var previous = index - 1; previous >= first; previous--) {
        final String declaration = lines[previous];
        final String name = RegExp.escape(expression);
        if (RegExp(
          '\\b(?:const\\s+)?(?:s?byte|u?short|u?int|u?long|float|double|decimal)\\s+$name\\b',
        ).hasMatch(declaration)) {
          return true;
        }
        final RegExpMatch? inferred = RegExp(
          '\\bvar\\s+$name\\s*=\\s*([^;]+)',
        ).firstMatch(declaration);
        if (inferred != null) {
          final String value = inferred.group(1)!.trim();
          return RegExp(
                r'^[+-]?\d[\d_]*(?:\.\d[\d_]*)?[fFdDmMuUlL]*$',
              ).hasMatch(value) ||
              RegExp(r'\.Ticks\b').hasMatch(value);
        }
      }
      return false;
    });
  }

  static bool _isStaticNumericConstant(
    String expression,
    String source,
  ) => RegExp(
    '\\bconst\\s+${RegExp.escape(expression)}\\s*=\\s*[0-9][0-9_]*(?:\\.[0-9_]+)?\\s*;',
  ).hasMatch(source);

  static bool _isAllowlistedSqlIdentifier(String expression, String source) {
    final RegExpMatch? loop = RegExp(
      '\\bfor\\s*\\(\\s*const\\s+${RegExp.escape(expression)}\\s+of\\s+'
      r'([A-Za-z_$][\w$]*)\s*\)',
    ).firstMatch(source);
    if (loop == null) return false;
    final RegExpMatch? declaration = RegExp(
      '\\bconst\\s+${RegExp.escape(loop.group(1)!)}\\s*=\\s*\\[([\\s\\S]*?)\\]\\s+as\\s+const',
    ).firstMatch(source);
    if (declaration == null) return false;
    final List<String> values = declaration
        .group(1)!
        .split(',')
        .map((String value) => value.trim())
        .where((String value) => value.isNotEmpty)
        .toList(growable: false);
    return values.isNotEmpty &&
        values.every(
          (String value) => RegExp(r'''^(['"])[^'"]+\1$''').hasMatch(value),
        );
  }

  static bool _isEfCoreParameterizedInterpolation(
    List<String> lines,
    int index,
  ) {
    final int start = index == 0 ? 0 : index - 1;
    final String invocation = lines.sublist(start, index + 1).join(' ');
    return RegExp(
      r'\bExecuteSqlInterpolated(?:Async)?\s*\(',
    ).hasMatch(invocation);
  }

  static final RegExp _parameterPlaceholderFactory = RegExp(
    r'''^(?:[A-Za-z_$][\w$]*\.map\(\s*\(\s*\)\s*=>\s*['"]\?['"]\s*\)|new\s+Array\([^)]*\)\.fill\(\s*['"]\?['"]\s*\))\.join\(\s*['"],['"]\s*\)$''',
  );

  static const Map<String, String> _why = <String, String>{
    'sql-select-star':
        'SELECT * couples callers to table layout and fetches unnecessary data.',
    'sql-delete-without-where':
        'DELETE without WHERE can remove every row in a table.',
    'sql-update-without-where': 'UPDATE without WHERE can modify every row.',
    'sql-drop-table-without-if-exists':
        'Unguarded destructive DDL makes migrations less repeatable.',
    'sql-not-in-subquery-null-risk':
        'A NULL returned by a NOT IN subquery can filter every row.',
    'sql-case-sensitive-like':
        'LIKE case behavior varies by database and collation.',
    'sql-leading-wildcard-like':
        'Leading wildcards generally prevent normal index use.',
    'sql-create-index-nonconcurrent':
        'PostgreSQL CREATE INDEX can lock writes.',
    'sql-add-not-null-default':
        'This migration can rewrite or lock large tables.',
    'sql-inline-string-concat':
        'String-built SQL can introduce injection and quoting bugs.',
  };
  static const Map<String, String> _suggestions = <String, String>{
    'sql-select-star': 'Select explicit columns.',
    'sql-delete-without-where':
        'Add a WHERE clause or document/suppress intentional full-table deletes.',
    'sql-update-without-where':
        'Add a WHERE clause or explicitly suppress an intentional full update.',
    'sql-drop-table-without-if-exists':
        'Use DROP TABLE IF EXISTS where appropriate.',
    'sql-not-in-subquery-null-risk':
        'Use NOT EXISTS or exclude NULL from the subquery.',
    'sql-case-sensitive-like':
        'Use ILIKE, normalized values, or documented collation.',
    'sql-leading-wildcard-like':
        'Use search indexes, trigram indexes, or prefix search.',
    'sql-create-index-nonconcurrent':
        'Use CREATE INDEX CONCURRENTLY when supported.',
    'sql-add-not-null-default':
        'Use a phased nullable, backfill, constraint migration.',
    'sql-inline-string-concat':
        'Use parameter placeholders and pass values separately.',
  };
}
