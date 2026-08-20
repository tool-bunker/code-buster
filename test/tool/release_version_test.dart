import 'package:test/test.dart';

import '../../tool/release_version.dart';

void main() {
  test('accepts a tag matching pubspec and the changelog heading', () {
    expect(
      validateReleaseVersion(
        tag: 'v0.1.0',
        pubspec: 'name: code_buster\nversion: 0.1.0\n',
        changelog: '# Changelog\n\n## 0.1.0\n\n- Initial release.\n',
      ),
      isNull,
    );
  });

  test('rejects a release missing its changelog heading', () {
    expect(
      validateReleaseVersion(
        tag: 'v0.2.0',
        pubspec: 'name: code_buster\nversion: 0.2.0\n',
        changelog: '# Changelog\n\n## 0.1.0\n',
      ),
      'CHANGELOG.md has no release heading for 0.2.0',
    );
  });

  test('rejects a tag that does not match pubspec', () {
    expect(
      validateReleaseVersion(
        tag: 'v0.2.0',
        pubspec: 'name: code_buster\nversion: 0.1.0\n',
        changelog: '# Changelog\n\n## 0.1.0\n',
      ),
      'tag v0.2.0 does not match pubspec version 0.1.0',
    );
  });
}
