import 'package:test/test.dart';

import '../../tool/release_notes.dart';

void main() {
  test('extracts only the requested changelog release body', () {
    const String changelog = '''
# Changelog

## 0.2.0

- Add UI drift analysis.
- Add Homebrew installation.

## 0.1.0

- Initial release.
''';

    expect(
      extractReleaseNotes(changelog: changelog, tag: 'v0.2.0'),
      '- Add UI drift analysis.\n- Add Homebrew installation.\n',
    );
  });

  test('rejects missing and empty release sections', () {
    expect(
      () => extractReleaseNotes(
        changelog: '# Changelog\n\n## 0.1.0\n\n- Initial.\n',
        tag: 'v0.2.0',
      ),
      throwsFormatException,
    );
    expect(
      () => extractReleaseNotes(
        changelog: '# Changelog\n\n## 0.2.0\n\n## 0.1.0\n',
        tag: 'v0.2.0',
      ),
      throwsFormatException,
    );
  });
}
