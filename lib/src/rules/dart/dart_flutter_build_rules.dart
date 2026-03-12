// Flutter build methods have special performance constraints, including allocation and side-effect patterns that ordinary Dart code may allow.

part of 'dart_advanced_rules.dart';

extension _DartFlutterBuildRules on _AdvancedDartVisitor {
  void _checkAsyncValuesInBuild(ClassDeclaration node) {
    for (final ClassMember member in node.body.members) {
      if (member is! MethodDeclaration || member.name.lexeme != 'build') {
        continue;
      }
      final String text = member.body.toSource();
      for (final RegExpMatch match in RegExp(
        r'future\s*:\s*([A-Za-z_]\w*)\s*\(',
      ).allMatches(text)) {
        final String call = match.group(1)!;
        if (call == 'Future') continue;
        _add(
          member,
          code: 'flutter-future-created-in-build',
          message: 'Future `$call()` is created during build',
          why:
              'Rebuilds restart the asynchronous operation and can duplicate work.',
          suggestion:
              'Create and retain the Future in initState or a state-management layer.',
        );
      }
      if (RegExp(r'\bStream(?:Controller)?(?:<[^>]+>)?\s*\(').hasMatch(text) ||
          RegExp(r'\bstream\s*:\s*[A-Za-z_]\w*\s*\(').hasMatch(text)) {
        _add(
          member,
          code: 'flutter-stream-created-in-build',
          message: 'a Stream or subscription source is created during build',
          why:
              'Rebuilds recreate asynchronous pipelines and can leak subscriptions or duplicate events.',
          suggestion:
              'Create and retain the Stream outside build, then reuse the stable instance.',
        );
      }
      final _GlobalKeyCreationVisitor globalKeys = _GlobalKeyCreationVisitor(
        member,
      );
      member.accept(globalKeys);
      if (globalKeys.hasUnmemoizedCreation) {
        _add(
          member,
          code: 'flutter-global-key-created-in-build',
          message: 'GlobalKey is created during build',
          why:
              'A new key on each rebuild discards element identity and associated state.',
          suggestion: 'Store the GlobalKey in a persistent State field.',
        );
      }
      final _FlutterBuildContractVisitor contracts =
          _FlutterBuildContractVisitor(member);
      member.accept(contracts);
      for (final AstNode scrollable in contracts.unboundedScrollables) {
        _add(
          scrollable,
          code: 'flutter-unbounded-scrollable',
          message: 'a scrollable may be unbounded inside a flex layout',
          why:
              'A scrollable without a bounded main-axis extent can fail layout at runtime.',
          suggestion:
              'Wrap it in Expanded, Flexible, or SizedBox, or set shrinkWrap intentionally.',
        );
      }
      for (final AstNode pointerControl
          in contracts.pointerControlsWithoutSemantics) {
        _add(
          pointerControl,
          code: 'flutter-gesture-semantic-gap',
          message: 'a raw pointer target is built without semantic context',
          why:
              'Pointer-only controls can be undiscoverable to screen readers and keyboard users.',
          suggestion:
              'Use a semantic button widget or provide Semantics and keyboard activation.',
        );
      }
      for (final AstNode expanded in contracts.expandedOutsideFlex) {
        _add(
          expanded,
          code: 'flutter-expanded-outside-flex',
          message:
              'Expanded is built without a surrounding Flex, Row, or Column',
          why:
              'Expanded requires Flex parent data and otherwise fails layout at runtime.',
          suggestion: 'Place Expanded directly under a Flex, Row, or Column.',
        );
      }
      for (final RegExpMatch match in RegExp(
        r'\bImage\.network\s*\(([^;]+)\)',
      ).allMatches(text)) {
        if (match.group(1)!.contains(RegExp(r'\berrorBuilder\s*:'))) continue;
        _add(
          member,
          code: 'flutter-image-network-no-error-builder',
          message: 'Image.network has no errorBuilder fallback',
          why:
              'Network and decoding failures otherwise surface as broken or inaccessible content.',
          suggestion:
              'Provide an errorBuilder with meaningful fallback content.',
        );
      }
    }
  }
}

final class _GlobalKeyCreationVisitor extends RecursiveAstVisitor<void> {
  _GlobalKeyCreationVisitor(this.buildMethod);

  final MethodDeclaration buildMethod;
  bool hasUnmemoizedCreation = false;

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    final String type = node.constructorName.type.toSource();
    if (RegExp(r'^GlobalKey(?:<.*>)?$').hasMatch(type) &&
        !_isDeferredCreation(node)) {
      hasUnmemoizedCreation = true;
    }
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (node.target == null &&
        node.methodName.name == 'GlobalKey' &&
        !_isDeferredCreation(node)) {
      hasUnmemoizedCreation = true;
    }
    super.visitMethodInvocation(node);
  }

  bool _isDeferredCreation(AstNode node) {
    AstNode? current = node.parent;
    while (current != null && !identical(current, buildMethod)) {
      if (current is FunctionExpression) {
        final AstNode? parent = current.parent;
        if (parent is NamedArgument) return true;
        if (parent is VariableDeclaration &&
            identical(parent.initializer, current)) {
          return true;
        }
        if (parent is AssignmentExpression &&
            identical(parent.rightHandSide, current)) {
          return true;
        }
        if (parent is ArgumentList) {
          final AstNode? invocation = parent.parent;
          if (invocation is MethodInvocation &&
              invocation.methodName.name == 'useMemoized') {
            return invocation.target == null &&
                parent.arguments.isNotEmpty &&
                identical(parent.arguments.first, current);
          }
          return true;
        }
        return false;
      }
      current = current.parent;
    }
    return false;
  }
}

final class _FlutterBuildContractVisitor extends RecursiveAstVisitor<void> {
  _FlutterBuildContractVisitor(this.buildMethod);

  final MethodDeclaration buildMethod;
  final List<AstNode> unboundedScrollables = <AstNode>[];
  final List<AstNode> pointerControlsWithoutSemantics = <AstNode>[];
  final List<AstNode> expandedOutsideFlex = <AstNode>[];

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    _record(node, node.constructorName.type.toSource(), node.toSource());
    super.visitInstanceCreationExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String name = node.methodName.name;
    if (_isWidgetName(name)) _record(node, name, node.toSource());
    super.visitMethodInvocation(node);
  }

  void _record(AstNode node, String type, String source) {
    final String? parent = _nearestWidgetParent(node);
    if (const <String>{'ListView', 'GridView'}.contains(type) &&
        const <String>{'Column', 'Row', 'Flex'}.contains(parent) &&
        !RegExp(r'\bshrinkWrap\s*:\s*true\b').hasMatch(source)) {
      unboundedScrollables.add(node);
    }
    if (type == 'Listener' &&
        RegExp(r'\bonPointer(?:Down|Up)\s*:').hasMatch(source) &&
        !RegExp(r'\bonPointerMove\s*:').hasMatch(source) &&
        !_hasSemanticAncestor(node)) {
      pointerControlsWithoutSemantics.add(node);
    }
    if (type == 'Expanded' &&
        const <String>{
          'Align',
          'Center',
          'ColoredBox',
          'Container',
          'DecoratedBox',
          'Padding',
          'SizedBox',
          'Stack',
        }.contains(parent)) {
      expandedOutsideFlex.add(node);
    }
  }

  String? _nearestWidgetParent(AstNode node) {
    AstNode? current = node.parent;
    while (current != null && !identical(current, buildMethod)) {
      final String? name = _widgetName(current);
      if (name != null) return name;
      current = current.parent;
    }
    return null;
  }

  bool _hasSemanticAncestor(AstNode node) {
    AstNode? current = node.parent;
    while (current != null && !identical(current, buildMethod)) {
      if (const <String>{
        'Semantics',
        'Tooltip',
      }.contains(_widgetName(current))) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  String? _widgetName(AstNode node) {
    if (node is InstanceCreationExpression) {
      return node.constructorName.type.toSource();
    }
    if (node is MethodInvocation) {
      final String methodName = node.methodName.name;
      if (_isWidgetName(methodName)) return methodName;
      final String? targetName = node.target?.toSource();
      if (targetName != null && _isWidgetName(targetName)) return targetName;
    }
    return null;
  }

  bool _isWidgetName(String name) =>
      name.isNotEmpty && name.codeUnitAt(0) >= 65 && name.codeUnitAt(0) <= 90;
}
