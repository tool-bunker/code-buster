// Flutter lifecycle ordering and cleanup bugs span method bodies, so these rules inspect state transitions rather than isolated lines.

part of 'dart_advanced_rules.dart';

extension _DartLifecycleRules on _AdvancedDartVisitor {
  void _checkOwnedResources(ClassDeclaration node, String text) {
    for (final FieldDeclaration declaration
        in node.body.members.whereType<FieldDeclaration>()) {
      final String type = (declaration.fields.type?.toSource() ?? '')
          .replaceFirst(RegExp(r'\?$'), '');
      if (!const <String>{
        'AnimationController',
        'PageController',
        'ScrollController',
        'TabController',
        'TextEditingController',
        'FocusNode',
      }.contains(type)) {
        continue;
      }
      for (final VariableDeclaration variable in declaration.fields.variables) {
        final String field = variable.name.lexeme;
        if (!field.startsWith('_') ||
            !_constructsController(text, field, type) ||
            RegExp(
              '${RegExp.escape(field)}[!?]?\\s*\\.\\s*dispose\\s*\\(',
            ).hasMatch(text)) {
          continue;
        }
        _add(
          variable,
          code: 'dart-controller-not-disposed',
          message: 'owned controller `$field` is not disposed',
          why:
              'Controllers and focus nodes retain listeners and native resources.',
          suggestion:
              'Dispose the owned resource from the class lifecycle method.',
        );
      }
    }
    const Map<String, ({String code, String kind, String action})> resources =
        <String, ({String code, String kind, String action})>{
          'Timer': (
            code: 'dart-timer-not-cancelled',
            kind: 'timer',
            action: 'cancel',
          ),
          'IOSink': (
            code: 'dart-iosink-not-closed',
            kind: 'sink',
            action: 'close',
          ),
          'HttpClient': (
            code: 'dart-http-client-not-closed',
            kind: 'HTTP client',
            action: 'close',
          ),
          'http.Client': (
            code: 'dart-http-client-not-closed',
            kind: 'HTTP client',
            action: 'close',
          ),
          'Isolate': (
            code: 'dart-isolate-not-terminated',
            kind: 'isolate',
            action: 'kill',
          ),
          'ReceivePort': (
            code: 'dart-receive-port-not-closed',
            kind: 'receive port',
            action: 'close',
          ),
          'RandomAccessFile': (
            code: 'dart-random-access-file-not-closed',
            kind: 'random-access file',
            action: 'close',
          ),
        };
    for (final FieldDeclaration declaration
        in node.body.members.whereType<FieldDeclaration>()) {
      final String type = (declaration.fields.type?.toSource() ?? '')
          .replaceFirst(RegExp(r'\?$'), '');
      if (type == node.namePart.typeName.lexeme) continue;
      final ({String code, String kind, String action})? resource =
          type.startsWith('StreamSink<')
          ? (code: 'dart-iosink-not-closed', kind: 'sink', action: 'close')
          : resources[type];
      if (resource == null) continue;
      for (final VariableDeclaration variable in declaration.fields.variables) {
        final String field = variable.name.lexeme;
        if (variable.initializer == null &&
            !RegExp(
              '\\b${RegExp.escape(field)}\\s*(?:\\?\\?=|=(?!=))',
            ).hasMatch(text)) {
          continue;
        }
        _checkClosableResource(
          node,
          text,
          field,
          code: resource.code,
          kind: resource.kind,
          action: resource.action,
        );
      }
    }
  }

  bool _constructsController(String text, String field, String type) => RegExp(
    '\\b${RegExp.escape(field)}\\s*(?:\\?\\?=|=(?!=))\\s*'
    '(?:const\\s+)?${RegExp.escape(type)}(?:\\s*\\.\\s*\\w+)?\\s*\\(',
  ).hasMatch(text);

  void _checkClosableResource(
    ClassDeclaration node,
    String text,
    String field, {
    required String code,
    required String kind,
    required String action,
  }) {
    if (RegExp(
      '${RegExp.escape(field)}[!?]?\\.$action\\s*\\(',
    ).hasMatch(text)) {
      return;
    }
    _add(
      node,
      code: code,
      message: 'owned $kind `$field` is not ${action}d',
      why: 'The live $kind retains operating-system or asynchronous resources.',
      suggestion:
          '${action[0].toUpperCase()}${action.substring(1)} the $kind during shutdown.',
    );
  }

  void _checkListeners(ClassDeclaration node) {
    final _ListenerLifecycleVisitor lifecycle = _ListenerLifecycleVisitor();
    node.accept(lifecycle);
    final Set<String> disposedTargets = lifecycle.disposedTargets;
    final Set<String> disposedAnimations = <String>{};
    for (final FieldDeclaration declaration
        in node.body.members.whereType<FieldDeclaration>()) {
      if (!(declaration.fields.type?.toSource() ?? '').startsWith(
        'Animation',
      )) {
        continue;
      }
      for (final VariableDeclaration variable in declaration.fields.variables) {
        final String initializer = variable.initializer?.toSource() ?? '';
        if (disposedTargets.any(
          (String target) =>
              RegExp('\\b${RegExp.escape(target)}\\b').hasMatch(initializer),
        )) {
          disposedAnimations.add(variable.name.lexeme);
        }
      }
    }
    for (final MapEntry<String, MethodInvocation> registration
        in lifecycle.registrations.entries) {
      final String callback = registration.value.argumentList.arguments.isEmpty
          ? ''
          : registration.value.argumentList.arguments.first.toSource();
      final String scopedCallback = lifecycle.scopedCallback(
        registration.value,
        callback,
      );
      if (lifecycle.removedTargets.contains(registration.key) ||
          (callback.isNotEmpty &&
              lifecycle.removedCallbacks.contains(scopedCallback)) ||
          disposedTargets.contains(registration.key) ||
          disposedAnimations.contains(registration.key) ||
          disposedTargets.any(registration.key.contains)) {
        continue;
      }
      _add(
        registration.value,
        code: 'flutter-listener-without-remove',
        message:
            'listener registered on `${registration.key}` is never removed',
        why: 'Unremoved listeners retain objects and can call disposed state.',
        suggestion: 'Remove the same listener during disposal.',
      );
    }
  }
}

final class _ListenerLifecycleVisitor extends RecursiveAstVisitor<void> {
  final Map<String, MethodInvocation> registrations =
      <String, MethodInvocation>{};
  final Set<String> removedTargets = <String>{};
  final Set<String> disposedTargets = <String>{};
  final Set<String> removedCallbacks = <String>{};

  String scopedCallback(AstNode node, String callback) {
    AstNode? current = node;
    while (current != null && current is! MethodDeclaration) {
      current = current.parent;
    }
    return '${current?.offset ?? -1}:$callback';
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final String? target = _targetName(node);
    if (target != null) {
      if (node.methodName.name == 'addListener') {
        registrations.putIfAbsent(target, () => node);
      } else if (node.methodName.name == 'removeListener') {
        removedTargets.add(target);
        if (node.argumentList.arguments.isNotEmpty) {
          removedCallbacks.add(
            scopedCallback(node, node.argumentList.arguments.first.toSource()),
          );
        }
      } else if (node.methodName.name == 'dispose') {
        disposedTargets.add(target);
      }
    }
    super.visitMethodInvocation(node);
  }

  String? _targetName(MethodInvocation node) {
    final String? source = node.realTarget?.toSource();
    if (source == null || source.isEmpty) return null;
    if (RegExp(r'^[A-Z]\w*(?:<[^>]+>)?(?:\.\w+)?\s*\(').hasMatch(source)) {
      AstNode? current = node.parent;
      while (current != null && current is! ClassMember) {
        if (current is VariableDeclaration) {
          return current.name.lexeme;
        }
        if (current is AssignmentExpression &&
            current.rightHandSide.offset <= node.offset &&
            node.end <= current.rightHandSide.end) {
          return current.leftHandSide.toSource();
        }
        current = current.parent;
      }
    }
    final String normalized = source
        .replaceFirst(RegExp(r'^this\.'), '')
        .replaceFirst(RegExp(r'[!?]+$'), '');
    return normalized;
  }
}
