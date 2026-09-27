import '../../core/models.dart';
import '../../core/regexp_cache.dart';
import 'oop_rules.dart';

const List<String> csharpOopBehaviorRuleIds = <String>[
  'oop-repeated-strategy-dispatch',
  'oop-state-behavior-candidate',
  'oop-feature-envy',
  'oop-service-locator-dependency',
  'oop-repeated-observer-notification',
  'oop-message-chain',
];

Map<String, List<Finding>> analyzeCSharpOopBehavior(CSharpOopProject project) {
  final List<Finding> strategy = <Finding>[];
  final List<Finding> state = <Finding>[];
  final List<Finding> envy = <Finding>[];
  final List<Finding> locators = <Finding>[];
  final List<Finding> observers = <Finding>[];
  final List<Finding> chains = <Finding>[];
  _strategyDispatch(project, strategy);
  _stateBehavior(project, state);
  _featureEnvy(project, envy);
  _serviceLocators(project, locators);
  _observerNotifications(project, observers);
  _messageChains(project, chains);
  return <String, List<Finding>>{
    'oop-repeated-strategy-dispatch': strategy,
    'oop-state-behavior-candidate': state,
    'oop-feature-envy': envy,
    'oop-service-locator-dependency': locators,
    'oop-repeated-observer-notification': observers,
    'oop-message-chain': chains,
  };
}

void _strategyDispatch(CSharpOopProject project, List<Finding> findings) {
  final Map<String, List<OopClass>> groups = <String, List<OopClass>>{};
  final RegExp switchPattern = cachedRegExp(
    r'\bswitch\s*\([^)]*\)\s*\{([^{}]*)\}',
    dotAll: true,
  );
  final RegExp labels = cachedRegExp(
    r'\bcase\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*:',
  );
  for (final OopClass owner in project.classes) {
    for (final OopMethod method in owner.methods) {
      for (final RegExpMatch match in switchPattern.allMatches(method.body)) {
        final List<String> variants =
            labels
                .allMatches(match.requiredGroup(1))
                .map((label) => label.requiredGroup(1))
                .toSet()
                .toList()
              ..sort();
        if (variants.length < 3) continue;
        groups.putIfAbsent(variants.join('|'), () => <OopClass>[]).add(owner);
      }
    }
  }
  for (final MapEntry<String, List<OopClass>> entry in groups.entries) {
    final Set<String> paths = entry.value.map((owner) => owner.path).toSet();
    if (entry.value.length < 3 || paths.length < 2) continue;
    final OopClass first = entry.value.first;
    findings.add(
      Finding(
        code: 'oop-repeated-strategy-dispatch',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            '${entry.value.length} switches repeat dispatch for ${entry.key.split('|').join(', ')} across ${paths.length} files',
        confidence: 'medium',
        relatedFiles: paths.where((path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
}

void _stateBehavior(CSharpOopProject project, List<Finding> findings) {
  for (final OopClass owner in project.classes.where(
    (type) => !type.isInterface,
  )) {
    final Map<String, int> switches = <String, int>{};
    final Map<String, Set<String>> labels = <String, Set<String>>{};
    for (final OopMethod method in owner.methods.where(
      (method) => !method.isStatic,
    )) {
      for (final RegExpMatch match in cachedRegExp(
        r'\bswitch\s*\(\s*(?:this\.)?(_?[A-Za-z_]\w*)\s*\)\s*\{([^{}]*)\}',
        dotAll: true,
      ).allMatches(method.body)) {
        final String field = match.requiredGroup(1);
        switches[field] = (switches[field] ?? 0) + 1;
        labels
            .putIfAbsent(field, () => <String>{})
            .addAll(
              cachedRegExp(r'\bcase\s+([^:]+):')
                  .allMatches(match.requiredGroup(2))
                  .map((item) => item.requiredGroup(1).trim()),
            );
      }
    }
    for (final MapEntry<String, int> entry in switches.entries) {
      final String field = entry.key;
      final Set<String>? fieldLabels = labels[field];
      if (entry.value < 3 ||
          fieldLabels == null ||
          fieldLabels.length < 3 ||
          !owner.fields.contains(field)) {
        continue;
      }
      findings.add(
        Finding(
          code: 'oop-state-behavior-candidate',
          severity: RuleSeverity.info,
          path: owner.path,
          line: owner.line,
          message:
              '${owner.name} repeats behavior over mutable state $field in ${entry.value} methods across ${fieldLabels.length} states',
          confidence: 'high',
        ),
      );
    }
  }
}

void _featureEnvy(CSharpOopProject project, List<Finding> findings) {
  for (final OopClass owner in project.classes) {
    for (final OopMethod method in owner.methods.where(
      (method) => !method.isStatic,
    )) {
      final int received = cachedRegExp(
        r'\b[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*',
      ).allMatches(method.body).length;
      for (final parameter in method.parameters) {
        final List<RegExpMatch> accesses = cachedRegExp(
          '\\b${RegExp.escape(parameter.name)}\\s*\\.\\s*([A-Za-z_]\\w*)',
        ).allMatches(method.body).toList();
        final Set<String> members = accesses
            .map((item) => item.requiredGroup(1))
            .toSet();
        if (accesses.length < 5 ||
            members.length < 3 ||
            accesses.length * 5 < received * 3) {
          continue;
        }
        findings.add(
          Finding(
            code: 'oop-feature-envy',
            severity: RuleSeverity.info,
            path: owner.path,
            line: owner.line,
            message:
                '${owner.name}.${method.name} accesses ${parameter.type} parameter ${parameter.name} ${accesses.length} times across ${members.length} members',
            confidence: 'high',
          ),
        );
        break;
      }
    }
  }
}

void _serviceLocators(CSharpOopProject project, List<Finding> findings) {
  final Map<String, List<({OopClass owner, Set<String> services})>> uses = {};
  final RegExp call = cachedRegExp(
    r'\b([A-Za-z_]\w*(?:Locator|Services|Container)|Locator|Services|Container)\s*\.\s*(?:[Gg]et|[Rr]esolve|[Gg]etService)\s*(?:<\s*([A-Za-z_]\w*)\s*>\s*\(|\(\s*([A-Za-z_]\w*)\.class)',
  );
  for (final OopClass owner in project.classes) {
    final Map<String, Set<String>> ownerUses = {};
    for (final OopMethod method in owner.methods) {
      for (final RegExpMatch match in call.allMatches(method.body)) {
        ownerUses
            .putIfAbsent(match.requiredGroup(1), () => <String>{})
            .add(match.group(2) ?? match.requiredGroup(3));
      }
    }
    for (final entry in ownerUses.entries) {
      uses.putIfAbsent(entry.key, () => []).add((
        owner: owner,
        services: entry.value,
      ));
    }
  }
  for (final entry in uses.entries) {
    final Set<String> paths = entry.value.map((use) => use.owner.path).toSet();
    final Set<String> services = entry.value
        .expand((use) => use.services)
        .toSet();
    if (entry.value.length < 3 || paths.length < 2 || services.length < 3) {
      continue;
    }
    final first = entry.value.first.owner;
    findings.add(
      Finding(
        code: 'oop-service-locator-dependency',
        severity: RuleSeverity.info,
        path: first.path,
        line: first.line,
        message:
            '${entry.key} resolves ${services.length} service types from ${entry.value.length} classes across ${paths.length} files',
        confidence: 'high',
        relatedFiles: paths.where((path) => path != first.path).toList()
          ..sort(),
      ),
    );
  }
}

void _observerNotifications(CSharpOopProject project, List<Finding> findings) {
  for (final OopClass owner in project.classes) {
    for (final String field in owner.fields) {
      final bool adds = owner.methods.any(
        (method) => cachedRegExp(
          '\\b${RegExp.escape(field)}\\s*\\.\\s*(?:[Aa]dd|push)\\s*\\(',
        ).hasMatch(method.body),
      );
      final bool removes = owner.methods.any(
        (method) => cachedRegExp(
          '\\b${RegExp.escape(field)}\\s*\\.\\s*(?:[Rr]emove|delete|splice)\\s*\\(',
        ).hasMatch(method.body),
      );
      if (!adds || !removes) continue;
      final Map<String, Set<String>> callbacks = {};
      final RegExp loop = cachedRegExp(
        '(?:foreach\\s*\\(\\s*(?:var|[A-Za-z_]\\w*)\\s+([A-Za-z_]\\w*)\\s+in\\s+|for\\s*\\(\\s*[A-Za-z_]\\w*(?:<[^>]+>)?\\s+([A-Za-z_]\\w*)\\s*:\\s*)(?:this\\.)?${RegExp.escape(field)}\\s*\\)\\s*\\{?\\s*([A-Za-z_]\\w*)\\s*\\.\\s*([A-Za-z_]\\w*)\\s*\\(',
        dotAll: true,
      );
      for (final OopMethod method in owner.methods) {
        for (final RegExpMatch match in loop.allMatches(method.body)) {
          final String? variable = match.group(1) ?? match.group(2);
          if (variable != match.group(3)) continue;
          callbacks
              .putIfAbsent(match.requiredGroup(4), () => <String>{})
              .add(method.name);
        }
        final RegExp typeScriptLoop = cachedRegExp(
          'for\\s*\\(\\s*(?:const|let)\\s+([A-Za-z_]\\w*)\\s+of\\s+(?:this\\.)?${RegExp.escape(field)}\\s*\\)\\s*\\{?\\s*\\1\\s*\\.\\s*([A-Za-z_]\\w*)\\s*\\(',
          dotAll: true,
        );
        for (final RegExpMatch match in typeScriptLoop.allMatches(
          method.body,
        )) {
          callbacks
              .putIfAbsent(match.requiredGroup(2), () => <String>{})
              .add(method.name);
        }
      }
      for (final entry in callbacks.entries.where(
        (entry) => entry.value.length >= 3,
      )) {
        findings.add(
          Finding(
            code: 'oop-repeated-observer-notification',
            severity: RuleSeverity.info,
            path: owner.path,
            line: owner.line,
            message:
                '${owner.name} repeats $field traversal calling ${entry.key} from ${entry.value.length} methods',
            confidence: 'high',
          ),
        );
      }
    }
  }
}

void _messageChains(CSharpOopProject project, List<Finding> findings) {
  final RegExp chain = cachedRegExp(
    r'\b[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\([^;()]*\))?){4,}',
  );
  for (final OopClass owner in project.classes) {
    var count = 0;
    var methods = 0;
    for (final OopMethod method in owner.methods) {
      final int current = chain.allMatches(method.body).length;
      if (current > 0) methods++;
      count += current;
    }
    if (count < 3 || methods < 2) continue;
    findings.add(
      Finding(
        code: 'oop-message-chain',
        severity: RuleSeverity.info,
        path: owner.path,
        line: owner.line,
        message:
            '${owner.name} contains $count collaboration chains of at least four hops across $methods methods',
        confidence: 'high',
      ),
    );
  }
}
