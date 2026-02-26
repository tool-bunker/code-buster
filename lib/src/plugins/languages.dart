// File extensions, aliases, and adapter registration define which languages Code Buster can actually recognize and invoke.

/// Metadata and selection for source-language analysis adapters.
final class LanguageDefinition {
  /// Creates metadata for one independently selectable source language.
  const LanguageDefinition({
    required this.id,
    required this.aliases,
    required this.extensions,
  });

  /// Canonical language identifier stored in findings and configuration.
  final String id;

  /// Accepted configuration and CLI aliases, excluding [id].
  final Set<String> aliases;

  /// Lowercase filename extensions owned by this language.
  final Set<String> extensions;

  /// Whether [value] selects this language.
  bool matches(String value) {
    final String normalized = value.toLowerCase();
    return id == normalized || aliases.contains(normalized);
  }
}

/// Source-language metadata registry. Parsing and rules remain in adapters.
final class LanguageRegistry {
  /// Creates a registry and rejects ambiguous identifiers, aliases, and files.
  LanguageRegistry(Iterable<LanguageDefinition> definitions)
    : _definitions = List<LanguageDefinition>.unmodifiable(definitions) {
    final Set<String> names = <String>{};
    final Set<String> extensions = <String>{};
    for (final LanguageDefinition definition in _definitions) {
      if (definition.id.isEmpty || !names.add(definition.id)) {
        throw ArgumentError.value(
          definition.id,
          'definitions',
          'Duplicate language identifier',
        );
      }
      for (final String name in <String>{
        definition.id,
        ...definition.aliases,
      }) {
        if (!names.add(name) && name != definition.id) {
          throw ArgumentError.value(
            name,
            'definitions',
            'Duplicate language alias',
          );
        }
      }
      for (final String extension in definition.extensions) {
        if (!extension.startsWith('.') || !extensions.add(extension)) {
          throw ArgumentError.value(
            extension,
            'definitions',
            'Invalid or duplicate extension',
          );
        }
      }
    }
  }

  /// Initial registry: Dart and Python have complete dependency adapters.
  factory LanguageRegistry.dartFirst() => LanguageRegistry(
    const <LanguageDefinition>[
      LanguageDefinition(
        id: 'cpp',
        aliases: <String>{'c++'},
        extensions: <String>{'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp'},
      ),
      LanguageDefinition(
        id: 'objective-c',
        aliases: <String>{'objc', 'objectivec'},
        extensions: <String>{'.m', '.mm'},
      ),
      LanguageDefinition(
        id: 'csharp',
        aliases: <String>{'cs'},
        extensions: <String>{'.cs'},
      ),
      LanguageDefinition(
        id: 'dart',
        aliases: <String>{},
        extensions: <String>{'.dart'},
      ),
      LanguageDefinition(
        id: 'nim',
        aliases: <String>{},
        extensions: <String>{'.nim', '.nims'},
      ),
      LanguageDefinition(
        id: 'python',
        aliases: <String>{'py'},
        extensions: <String>{'.py'},
      ),
      LanguageDefinition(
        id: 'javascript',
        aliases: <String>{'js'},
        extensions: <String>{'.js', '.jsx', '.mjs', '.cjs'},
      ),
      LanguageDefinition(
        id: 'typescript',
        aliases: <String>{'ts'},
        extensions: <String>{'.ts', '.tsx', '.mts', '.cts'},
      ),
      LanguageDefinition(
        id: 'go',
        aliases: <String>{'golang'},
        extensions: <String>{'.go', '.mod'},
      ),
      LanguageDefinition(
        id: 'html',
        aliases: <String>{'htm'},
        extensions: <String>{'.html', '.htm'},
      ),
      LanguageDefinition(
        id: 'css',
        aliases: <String>{},
        extensions: <String>{'.css'},
      ),
      LanguageDefinition(
        id: 'java',
        aliases: <String>{},
        extensions: <String>{'.java'},
      ),
      LanguageDefinition(
        id: 'wren',
        aliases: <String>{},
        extensions: <String>{'.wren'},
      ),
      LanguageDefinition(
        id: 'sql',
        aliases: <String>{'postgres', 'postgresql', 'mysql'},
        extensions: <String>{'.sql'},
      ),
      LanguageDefinition(
        id: 'lua',
        aliases: <String>{'luau'},
        extensions: <String>{'.lua', '.luau'},
      ),
    ],
  );

  final List<LanguageDefinition> _definitions;

  /// Registered definitions in deterministic registration order.
  List<LanguageDefinition> get definitions => _definitions;

  /// All extensions discoverable by the registered language adapters.
  Set<String> get extensions => Set<String>.unmodifiable(
    _definitions.expand(
      (LanguageDefinition definition) => definition.extensions,
    ),
  );

  /// Resolves a configured identifier or alias, returning null when unknown.
  LanguageDefinition? lookup(String value) {
    final String normalized = value.toLowerCase();
    for (final LanguageDefinition definition in _definitions) {
      if (definition.matches(normalized)) {
        return definition;
      }
    }
    return null;
  }

  /// Resolves `auto` or the requested language identifiers without duplicates.
  List<LanguageDefinition> select(Iterable<String> requested) {
    final List<String> selections = requested.toList(growable: false);
    if (selections.isEmpty ||
        selections.any((String value) => value.toLowerCase() == 'auto')) {
      return _definitions;
    }

    final Set<String> selected = <String>{};
    final List<LanguageDefinition> result = <LanguageDefinition>[];
    for (final String value in selections) {
      if (value.toLowerCase() == 'frontend' || value.toLowerCase() == 'web') {
        for (final String id in <String>['html', 'css']) {
          final LanguageDefinition definition = lookup(id)!;
          if (selected.add(definition.id)) result.add(definition);
        }
        continue;
      }
      final LanguageDefinition? definition = lookup(value);
      if (definition == null) {
        throw FormatException('Unknown Code Buster language: $value');
      }
      if (selected.add(definition.id)) {
        result.add(definition);
      }
    }
    return List<LanguageDefinition>.unmodifiable(result);
  }
}
