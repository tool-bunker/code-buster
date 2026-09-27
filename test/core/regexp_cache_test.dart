import 'package:code_buster/src/core/regexp_cache.dart';
import 'package:test/test.dart';

void main() {
  test('reuses expressions only when pattern options match', () {
    final RegExp first = cachedRegExp('token', caseSensitive: false);
    final RegExp repeated = cachedRegExp('token', caseSensitive: false);
    final RegExp caseSensitive = cachedRegExp('token');

    expect(identical(first, repeated), isTrue);
    expect(identical(first, caseSensitive), isFalse);
    expect(first.hasMatch('TOKEN'), isTrue);
    expect(caseSensitive.hasMatch('TOKEN'), isFalse);
  });

  test('requires captures declared mandatory by their consumer', () {
    final RegExpMatch match = cachedRegExp(
      r'(required)(?:-(optional))?',
    ).firstMatch('required')!;

    expect(match.requiredGroup(1), 'required');
    expect(() => match.requiredGroup(2), throwsStateError);
  });
}
