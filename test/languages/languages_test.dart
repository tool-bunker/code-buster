import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

void main() {
  final LanguageRegistry registry = LanguageRegistry(<LanguageDefinition>[
    const LanguageDefinition(
      id: 'dart',
      aliases: <String>{'flutter'},
      extensions: <String>{'.dart'},
    ),
    const LanguageDefinition(
      id: 'typescript',
      aliases: <String>{'ts', 'javascript', 'js'},
      extensions: <String>{'.ts', '.tsx', '.js', '.jsx'},
    ),
  ]);

  test('registered language families expose aliases and extensions', () {
    final LanguageRegistry registry = LanguageRegistry.dartFirst();

    expect(registry.lookup('c++')?.id, 'cpp');
    expect(registry.lookup('cs')?.id, 'csharp');
    expect(registry.lookup('objc')?.id, 'objective-c');
    expect(registry.lookup('flutter'), isNull);
    expect(registry.lookup('py')?.id, 'python');
    expect(registry.lookup('ts')?.id, 'typescript');
    expect(registry.lookup('frontend'), isNull);
    expect(
      registry
          .select(<String>['frontend'])
          .map((LanguageDefinition item) => item.id),
      <String>['html', 'css'],
    );
    expect(registry.lookup('go')?.id, 'go');
    expect(registry.lookup('golang')?.id, 'go');
    expect(registry.lookup('java')?.id, 'java');
    expect(registry.lookup('nim')?.id, 'nim');
    expect(registry.lookup('rust')?.id, 'rust');
    expect(registry.lookup('rs')?.id, 'rust');
    expect(registry.lookup('mojo')?.id, 'mojo');
    expect(registry.lookup('postgresql')?.id, 'sql');
    expect(registry.lookup('wren')?.id, 'wren');
    expect(registry.lookup('luau')?.id, 'lua');
    expect(registry.extensions, <String>{
      '.c',
      '.cc',
      '.cpp',
      '.cxx',
      '.h',
      '.hh',
      '.hpp',
      '.m',
      '.mm',
      '.cs',
      '.dart',
      '.rs',
      '.mojo',
      '.go',
      '.mod',
      '.py',
      '.js',
      '.jsx',
      '.mjs',
      '.cjs',
      '.ts',
      '.tsx',
      '.mts',
      '.cts',
      '.lua',
      '.luau',
      '.java',
      '.nim',
      '.nims',
      '.sql',
      '.html',
      '.htm',
      '.css',
      '.wren',
    });
  });

  test('resolves aliases and preserves selection order', () {
    final List<LanguageDefinition> selected = registry.select(<String>[
      'flutter',
      'typescript',
      'dart',
    ]);

    expect(selected.map((LanguageDefinition item) => item.id), <String>[
      'dart',
      'typescript',
    ]);
  });

  test('auto selects every registered adapter', () {
    final List<LanguageDefinition> selected = registry.select(<String>['auto']);

    expect(selected.map((LanguageDefinition item) => item.id), <String>[
      'dart',
      'typescript',
    ]);
    expect(registry.extensions, <String>{
      '.dart',
      '.ts',
      '.tsx',
      '.js',
      '.jsx',
    });
  });

  test('rejects unknown languages and ambiguous aliases', () {
    expect(() => registry.select(<String>['nim']), throwsFormatException);
    expect(
      () => LanguageRegistry(<LanguageDefinition>[
        const LanguageDefinition(
          id: 'dart',
          aliases: <String>{'flutter'},
          extensions: <String>{'.dart'},
        ),
        const LanguageDefinition(
          id: 'other',
          aliases: <String>{'flutter'},
          extensions: <String>{'.other'},
        ),
      ]),
      throwsArgumentError,
    );
  });
}
