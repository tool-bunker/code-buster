import 'dart:io';

import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  group('SafeFixer', () {
    const SafeFixer fixer = SafeFixer();

    test('normalizes indentation and trailing whitespace outside literals', () {
      expect(
        fixer.fixedContent(
          '\tvoid main() {  \n\tprint("left\tmiddle");  \n}\n',
        ),
        '  void main() {\n  print("left\tmiddle");\n}\n',
      );
    });

    test('preserves multiline string data byte-for-byte', () {
      expect(
        fixer.fixedContent('final String text = """\n\tcontent  \n""";  \n'),
        'final String text = """\n\tcontent  \n""";\n',
      );
    });

    test('retains CRLF and final-newline state', () {
      expect(
        fixer.fixedContent('\tfinal value = 1;  \r\n'),
        '  final value = 1;\r\n',
      );
      expect(fixer.fixedContent('\tfinal value = 1;  '), '  final value = 1;');
    });

    test('rewrites safe Nim standard-library imports', () {
      expect(
        fixer.fixedContent(
          'import os\nfrom os import getEnv\nimport os, strutils\n',
          path: 'src/main.nim',
        ),
        'import std/os\nfrom std/os import getEnv\nimport std/os, strutils\n',
      );
    });

    test(
      'dry run never writes and apply writes only changed content',
      () async {
        final Directory root = await Directory.systemTemp.createTemp(
          'code-buster-fixer-',
        );
        addTearDown(() => root.delete(recursive: true));
        final File file = File('${root.path}${Platform.pathSeparator}main.dart')
          ..writeAsStringSync('\tvoid main() {}  \n');
        final SourceFile source = SourceFile(
          relativePath: 'main.dart',
          absolutePath: file.path,
          language: 'dart',
        );

        final List<FixResult> preview = fixer.apply(
          root: root.path,
          files: <SourceFile>[source],
          dryRun: true,
        );
        expect(preview.single.changed, isTrue);
        expect(file.readAsStringSync(), '\tvoid main() {}  \n');

        final List<FixResult> applied = fixer.apply(
          root: root.path,
          files: <SourceFile>[source],
          dryRun: false,
        );
        expect(applied.single.changed, isTrue);
        expect(file.readAsStringSync(), '  void main() {}\n');
      },
    );
  });
}
