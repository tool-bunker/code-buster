// Reuses compiled constant regular expressions in repeated analysis paths.

const int _maximumCachedExpressions = 512;

final Map<
  ({
    String pattern,
    bool multiLine,
    bool caseSensitive,
    bool unicode,
    bool dotAll,
  }),
  RegExp
>
_regExpCache =
    <
      ({
        String pattern,
        bool multiLine,
        bool caseSensitive,
        bool unicode,
        bool dotAll,
      }),
      RegExp
    >{};

/// Returns a shared compiled regular expression for a stable analysis pattern.
///
/// The bounded cache also tolerates callers whose pattern comes from project
/// configuration without retaining an unbounded number of expressions.
RegExp cachedRegExp(
  String pattern, {
  bool multiLine = false,
  bool caseSensitive = true,
  bool unicode = false,
  bool dotAll = false,
}) {
  final key = (
    pattern: pattern,
    multiLine: multiLine,
    caseSensitive: caseSensitive,
    unicode: unicode,
    dotAll: dotAll,
  );
  final RegExp? existing = _regExpCache.remove(key);
  if (existing != null) {
    _regExpCache[key] = existing;
    return existing;
  }
  final RegExp expression = RegExp(
    pattern,
    multiLine: multiLine,
    caseSensitive: caseSensitive,
    unicode: unicode,
    dotAll: dotAll,
  );
  _regExpCache[key] = expression;
  if (_regExpCache.length > _maximumCachedExpressions) {
    _regExpCache.remove(_regExpCache.keys.first);
  }
  return expression;
}

/// Accesses a capture group that is mandatory in the pattern's contract.
extension RequiredPatternCapture on Match {
  /// Returns capture [index], or fails with context when the pattern contract
  /// and its consumer have drifted apart.
  String requiredGroup(int index) {
    final String? value = group(index);
    if (value == null) {
      throw StateError('Pattern capture $index is absent in $pattern');
    }
    return value;
  }
}

/// Accesses named captures declared mandatory by a regular expression.
extension RequiredRegExpNamedCapture on RegExpMatch {
  /// Returns named capture [name], or reports a violated pattern invariant.
  String requiredNamedGroup(String name) {
    final String? value = namedGroup(name);
    if (value == null) {
      throw StateError('Pattern capture `$name` is absent in $pattern');
    }
    return value;
  }
}
