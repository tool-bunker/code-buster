// Each language must expose exactly one local registry; this switch is the junction between plugin IDs and executable rule sets.

import '../core/rule.dart';
import 'cpp/rules.dart';
import 'csharp/rules.dart';
import 'dart/rules.dart';
import 'frontend/rules.dart';
import 'go/rules.dart';
import 'java/rules.dart';
import 'javascript/rules.dart';
import 'lua/rules.dart';
import 'mojo/rules.dart';
import 'nim/rules.dart';
import 'python/rules.dart';
import 'rust/rules.dart';
import 'sql/rules.dart';
import 'wren/rules.dart';

/// Per-language rule manifests keyed by discovery language ID.
final Map<String, RuleRegistry> languageRuleRegistries = <String, RuleRegistry>{
  'cpp': cppRuleRegistry,
  'csharp': csharpRuleRegistry,
  'css': cssRuleRegistry,
  'dart': dartRuleRegistry,
  'go': goRuleRegistry,
  'html': htmlRuleRegistry,
  'java': javaRuleRegistry,
  'javascript': javascriptRuleRegistry,
  'lua': luaRuleRegistry,
  'mojo': mojoRuleRegistry,
  'nim': nimRuleRegistry,
  'python': pythonRuleRegistry,
  'rust': rustRuleRegistry,
  'sql': sqlRuleRegistry,
  'wren': wrenRuleRegistry,
};

/// Returns a language manifest and fails if built-in wiring is incomplete.
RuleRegistry languageRules(String language) {
  final RuleRegistry? registry = languageRuleRegistries[language];
  if (registry != null) return registry;
  throw StateError('No rule manifest registered for $language');
}
