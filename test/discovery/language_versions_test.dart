import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

void main() {
  test('detects declared language and runtime constraints', () {
    final Directory root = Directory.systemTemp.createTempSync('cb-versions-');
    addTearDown(() => root.deleteSync(recursive: true));
    void write(String relative, String source) {
      File(path.join(root.path, relative))
        ..createSync(recursive: true)
        ..writeAsStringSync(source);
    }

    write('pubspec.yaml', 'environment:\n  sdk: ">=3.5.0 <4.0.0"\n');
    write(
      'web/package.json',
      '{"engines":{"node":">=20"},"devDependencies":{"typescript":"^5.7.0"}}',
    );
    write('service/go.mod', 'module example.test/service\ngo 1.23\n');
    write('python/pyproject.toml', 'requires-python = ">=3.12"\n');
    write(
      'java/pom.xml',
      '<properties><maven.compiler.release>21</maven.compiler.release></properties>',
    );
    write('node_modules/ignored/package.json', '{"engines":{"node":"1"}}');

    expect(const LanguageVersionDetector().detect(root.path), <String, String>{
      'dart': '>=3.5.0 <4.0.0',
      'java': '21',
      'python': '>=3.12',
      'go': '1.23',
      'node': '>=20',
      'typescript': '^5.7.0',
    });
  });
}
