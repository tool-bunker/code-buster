import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  test('previews selected files without creating an analysis cache', () async {
    final Directory root = await Directory.systemTemp.createTemp('cb-preview-');
    addTearDown(() => root.delete(recursive: true));
    File(path.join(root.path, 'lib', 'main.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void main() {}\n');
    File(path.join(root.path, 'test', 'main_test.dart'))
      ..createSync(recursive: true)
      ..writeAsStringSync('void main() {}\n');

    final ProcessResult result = await Process.run(
      Platform.resolvedExecutable,
      <String>[
        'run',
        'bin/cb.dart',
        'preview',
        '--root',
        root.path,
        '--format',
        'json',
      ],
      workingDirectory: Directory.current.path,
    );

    expect(result.exitCode, 0, reason: result.stderr as String);
    final Map<String, Object?> report =
        jsonDecode(result.stdout as String) as Map<String, Object?>;
    expect(report['command'], 'preview');
    expect(report['files'], <Object?>[
      <String, String>{'path': 'lib/main.dart', 'language': 'dart'},
    ]);
    expect((report['coverage']! as Map<String, Object?>)['test'], 1);
    expect(
      Directory(path.join(root.path, '.code-buster-cache')).existsSync(),
      isFalse,
    );
  });
}
