// Dart can be parsed semantically with package:analyzer, giving rules reliable declarations, imports, exports, and function boundaries.

import 'package:analyzer/dart/analysis/features.dart';
import 'package:analyzer/dart/analysis/results.dart';
import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:path/path.dart' as path;

import '../../engine/analysis.dart';
import '../../graph/graph.dart';

/// Parsed Dart library directives and public top-level declarations.
final class DartUnit {
  /// Creates one parsed Dart compilation unit summary.
  const DartUnit({
    required this.imports,
    required this.exports,
    required this.parts,
    required this.publicDeclarations,
  });

  /// URI strings from `import` directives.
  final List<String> imports;

  /// URI strings from `export` directives.
  final List<String> exports;

  /// URI strings from `part` directives.
  final List<String> parts;

  /// Public top-level declaration names.
  final List<String> publicDeclarations;
}

/// One structured Dart parser diagnostic.
final class DartParseDiagnostic {
  /// Creates a parser diagnostic.
  const DartParseDiagnostic({required this.line, required this.message});

  /// One-based source line.
  final int line;

  /// Analyzer diagnostic message.
  final String message;
}

/// Parsed Dart unit and its recoverable parser diagnostics.
final class DartParseResult {
  /// Creates a detailed parse result.
  const DartParseResult({required this.unit, required this.diagnostics});

  /// Recovered compilation unit.
  final CompilationUnit unit;

  /// Syntax diagnostics emitted while recovering the unit.
  final List<DartParseDiagnostic> diagnostics;
}

/// Parses Dart directives with the Dart analyzer rather than source regexes.
final class DartSourceParser {
  /// Parses [source] without rejecting a partially edited compilation unit.
  DartUnit parse(String source, {String sourcePath = ''}) =>
      summarize(parseCompilationUnit(source, sourcePath: sourcePath));

  /// Parses a compilation unit for reuse by graph and rule analysis.
  CompilationUnit parseCompilationUnit(
    String source, {
    String sourcePath = '',
  }) => parseDetailed(source, sourcePath: sourcePath).unit;

  /// Parses source while preserving syntax diagnostics and recovered AST.
  DartParseResult parseDetailed(String source, {String sourcePath = ''}) {
    var result = _parse(source, sourcePath);
    if (result.errors.isNotEmpty) {
      final String compatible = _normalizeCompatibilitySyntax(source);
      if (compatible != source) {
        final fallback = _parse(compatible, sourcePath);
        if (fallback.errors.length < result.errors.length) result = fallback;
      }
    }
    return DartParseResult(
      unit: result.unit,
      diagnostics: <DartParseDiagnostic>[
        for (final error in result.errors)
          DartParseDiagnostic(
            line: result.lineInfo.getLocation(error.offset).lineNumber,
            message: error.message,
          ),
      ],
    );
  }

  ParseStringResult _parse(String source, String sourcePath) => parseString(
    content: source,
    path: sourcePath,
    featureSet: FeatureSet.latestLanguageVersion(),
    throwIfDiagnostics: false,
  );

  String _normalizeCompatibilitySyntax(String source) => source
      .replaceAllMapped(
        RegExp(
          r'for\s*\(\s*final\s+MapEntry\(key:\s*([A-Za-z_]\w*),\s*value:\s*([A-Za-z_]\w*)\)\s+in\s+([^\n]+?)\)\s*\{',
        ),
        (Match match) =>
            'for (final _cbEntry in ${match.group(3)}) { final ${match.group(1)} = _cbEntry.key; final ${match.group(2)} = _cbEntry.value;',
      )
      .replaceAllMapped(
        RegExp(r'\brequired(\s+)final\b'),
        (Match match) => 'required${match.group(1)}     ',
      )
      .replaceAllMapped(
        RegExp(r'(@[A-Za-z_]\w*(?:\([^)]*\))?[ \t]+)final(?=[ \t]+[A-Za-z_])'),
        (Match match) => '${match.group(1)}     ',
      )
      .replaceAllMapped(
        RegExp(r'({[ \t]*)final(?=[ \t]+[A-Za-z_])'),
        (Match match) => '${match.group(1)}     ',
      )
      .replaceAllMapped(
        RegExp(r'([[(,]\s*)final(?=\s+[A-Za-z_])'),
        (Match match) => '${match.group(1)}     ',
      )
      .replaceAllMapped(
        RegExp(r'(\(\s*\(\s*)var(?=\s+[A-Za-z_]\w*)'),
        (Match match) => '${match.group(1)}   ',
      )
      .replaceAllMapped(
        RegExp(
          r'^(\s*)final(?=[ \t]+(?:void|Future(?:<[^>]+>)?)[ \t]+Function\b)',
          multiLine: true,
        ),
        (Match match) => '${match.group(1)}     ',
      )
      .replaceAllMapped(
        RegExp(
          r'^(\s*)final(?=\s+[A-Za-z_][^=;\n]*\s+[A-Za-z_]\w*(?:\s*=|,|\)))',
          multiLine: true,
        ),
        (Match match) => '${match.group(1)}     ',
      );

  /// Extracts callable bodies from parsed Dart units for shared complexity rules.
  List<FunctionSource> functionsParsed(Map<String, CompilationUnit> units) {
    final List<FunctionSource> result = <FunctionSource>[];
    for (final MapEntry<String, CompilationUnit> entry in units.entries) {
      entry.value.accept(_DartFunctionVisitor(entry.key, entry.value, result));
    }
    return List<FunctionSource>.unmodifiable(result);
  }

  /// Extracts dependency and declaration summaries from [unit].
  DartUnit summarize(CompilationUnit unit) {
    final List<String> imports = <String>[];
    final List<String> exports = <String>[];
    final List<String> parts = <String>[];
    for (final Directive directive in unit.directives) {
      if (directive case ImportDirective(uri: final StringLiteral uri)) {
        final String? value = uri.stringValue;
        if (value != null) {
          imports.add(value);
        }
      } else if (directive case ExportDirective(uri: final StringLiteral uri)) {
        final String? value = uri.stringValue;
        if (value != null) {
          exports.add(value);
        }
      } else if (directive case PartDirective(uri: final StringLiteral uri)) {
        final String? value = uri.stringValue;
        if (value != null) {
          parts.add(value);
        }
      }
    }
    return DartUnit(
      imports: List<String>.unmodifiable(imports),
      exports: List<String>.unmodifiable(exports),
      parts: List<String>.unmodifiable(parts),
      publicDeclarations: List<String>.unmodifiable(_publicDeclarations(unit)),
    );
  }

  List<String> _publicDeclarations(CompilationUnit unit) {
    final Set<String> names = <String>{};
    for (final CompilationUnitMember member in unit.declarations) {
      final RegExpMatch? match = RegExp(
        r'^(?:abstract\s+|base\s+|final\s+|sealed\s+|interface\s+)?'
        r'(?:(?:class|enum)(?:\s+const)?|mixin(?:\s+class)?|'
        r'extension(?:\s+type)?|typedef)\s+([A-Za-z_]\w*)',
        multiLine: true,
      ).firstMatch(member.toSource());
      if (match != null && !match.group(1)!.startsWith('_')) {
        names.add(match.group(1)!);
      }
      final RegExpMatch? callable = RegExp(
        r'^(?:[A-Za-z_]\w*(?:<[^>]+>)?\s+)+([A-Za-z_]\w*)\s*(?:<[^>]+>)?\s*\(',
        multiLine: true,
      ).firstMatch(member.toSource());
      if (callable != null && !callable.group(1)!.startsWith('_')) {
        names.add(callable.group(1)!);
      }
      final RegExpMatch? variable = RegExp(
        r'^(?:const|final|var|late)\s+(?:[A-Za-z_]\w*(?:<[^>]+>)?\s+)?([A-Za-z_]\w*)',
        multiLine: true,
      ).firstMatch(member.toSource());
      if (variable != null && !variable.group(1)!.startsWith('_')) {
        names.add(variable.group(1)!);
      }
    }
    return names.toList()..sort();
  }
}

final class _DartFunctionVisitor extends RecursiveAstVisitor<void> {
  _DartFunctionVisitor(this.path, this.unit, this.result);

  final String path;
  final CompilationUnit unit;
  final List<FunctionSource> result;

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    _add(node, node.name.lexeme, node.functionExpression.body);
    super.visitFunctionDeclaration(node);
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    _add(node, node.name.lexeme, node.body);
    super.visitMethodDeclaration(node);
  }

  @override
  void visitConstructorDeclaration(ConstructorDeclaration node) {
    final String suffix = node.name == null ? '' : '.${node.name!.lexeme}';
    _add(node, '${node.typeName?.name ?? 'new'}$suffix', node.body);
    super.visitConstructorDeclaration(node);
  }

  @override
  void visitPrimaryConstructorBody(PrimaryConstructorBody node) {
    final String name = node.declaration?.typeName.lexeme ?? 'new';
    _add(node, name, node.body);
    super.visitPrimaryConstructorBody(node);
  }

  void _add(AstNode node, String name, FunctionBody body) {
    if (body is EmptyFunctionBody) return;
    result.add(
      FunctionSource(
        path: path,
        name: name,
        line: unit.lineInfo.getLocation(node.offset).lineNumber,
        source: node.toSource(),
      ),
    );
  }
}

/// Resolves local Dart directives and produces core dependency graph edges.
final class DartGraphAdapter {
  /// Creates an adapter rooted at [root] for the local [packageName].
  DartGraphAdapter({required this.root, required this.packageName});

  /// Absolute project root.
  final String root;

  /// Local Dart package name used for `package:` URI resolution.
  final String packageName;

  /// Builds a local-file dependency graph from project-relative Dart sources.
  DependencyGraph build(Map<String, String> sources) {
    final DartSourceParser parser = DartSourceParser();
    return buildParsed(sources, <String, CompilationUnit>{
      for (final MapEntry<String, String> source in sources.entries)
        source.key: parser.parseCompilationUnit(
          source.value,
          sourcePath: source.key,
        ),
    });
  }

  /// Builds a graph from compilation units already parsed by the plugin.
  DependencyGraph buildParsed(
    Map<String, String> sources,
    Map<String, CompilationUnit> units,
  ) {
    final DartSourceParser parser = DartSourceParser();
    final Map<String, Iterable<String>> edges = <String, Iterable<String>>{};
    final List<String> files = sources.keys.toList()..sort();
    for (final String sourcePath in files) {
      final DartUnit unit = parser.summarize(units[sourcePath]!);
      final Set<String> dependencies = <String>{};
      for (final String uri in <String>[
        ...unit.imports,
        ...unit.exports,
        ...unit.parts,
      ]) {
        final String? target = _resolve(sourcePath, uri, sources.keys.toSet());
        if (target != null) {
          dependencies.add(target);
        }
      }
      edges[sourcePath] = dependencies;
    }
    return DependencyGraph(edges);
  }

  String? _resolve(String sourcePath, String uri, Set<String> knownFiles) {
    if (uri.startsWith('dart:')) {
      return null;
    }
    String candidate;
    if (uri.startsWith('package:')) {
      final String packageUri = uri.substring('package:'.length);
      final int separator = packageUri.indexOf('/');
      final String package = separator < 0
          ? packageUri
          : packageUri.substring(0, separator);
      if (package != packageName || separator < 0) {
        return null;
      }
      candidate = path.posix.normalize(
        'lib/${packageUri.substring(separator + 1)}',
      );
    } else {
      candidate = path.posix.normalize(
        path.posix.join(path.posix.dirname(sourcePath), uri),
      );
    }
    return knownFiles.contains(candidate) ? candidate : null;
  }
}
