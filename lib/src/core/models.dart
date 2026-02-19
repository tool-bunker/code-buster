// The analyzer, rules, controls, and reporters communicate through these immutable value objects rather than loosely shaped maps.

import 'dart:convert';

import 'package:crypto/crypto.dart';

enum RuleSeverity {
  info,

  warn,

  error;

  /// Parses Code Buster configuration severity spelling, including `warning`.
  static RuleSeverity parse(String value) => switch (value.toLowerCase()) {
    'info' => RuleSeverity.info,
    'warn' || 'warning' => RuleSeverity.warn,
    'error' => RuleSeverity.error,
    _ => throw FormatException('Unknown Code Buster severity: $value'),
  };

  String get configValue => name;
}

final class PatternRule {
  const PatternRule({
    required this.id,
    required this.severity,
    required this.pattern,
    required this.message,
    this.suggestion = '',
    this.patternNot = '',
    this.fix = '',
    this.category = '',
  });

  final String id;

  final RuleSeverity severity;

  final String pattern;

  final String message;

  final String suggestion;

  final String patternNot;

  final String fix;

  final String category;
}

enum DuplicationMode {
  /// Preserve identifiers and literals when comparing normalized source lines.
  exact,

  /// Also compare function structure with identifiers and literals normalized.
  normalized,

  /// Also detect separate implementations of the same external contract.
  semantic,
}

enum RuleMode {
  /// Emit individual findings and include them in default quality gates.
  report,

  /// Analyze the rule but show only aggregate counts by default.
  count,

  /// Do not execute the rule.
  off;

  /// Parses a rule-mode configuration value.
  static RuleMode parse(String value) => switch (value.toLowerCase()) {
    'report' => RuleMode.report,
    'count' => RuleMode.count,
    'off' => RuleMode.off,
    _ => throw FormatException('Unknown Code Buster rule mode: $value'),
  };

  String get configValue => name;
}

final class AnalysisConfig {
  const AnalysisConfig({
    required this.root,
    this.language = 'auto',
    this.languages = const <String>[],
    this.entryPoints = const <String>[],
    this.includes = const <String>[],
    this.excludes = const <String>[],
    this.changedBase = '',
    this.changedLines = false,
    this.ignorePatterns = const <String>[],
    this.classificationProduction = const <String>[],
    this.classificationTest = const <String>[],
    this.classificationGenerated = const <String>[],
    this.minDuplicationLines = 15,
    this.duplicationMode = DuplicationMode.exact,
    this.complexityThreshold = 10,
    this.cognitiveThreshold = 15,
    this.maxFileLines = 0,
    this.maxFunctionLines = 0,
    this.csharpDeadCode = false,
    this.qualityProfile = 'standard',
    this.qualityGates = const <String>['findings == 0'],
    this.ruleGroups = const <String>{
      'core',
      'correctness',
      'security',
      'reliability',
      'accessibility',
      'performance',
      'maintainability',
      'style',
      'nim-style',
      'suspicious',
      'design',
      'yagni',
      'regex',
      'sql',
      'idiomatic',
      'nim-advanced',
      'strings',
      'zerocost',
    },
    this.disabledRules = const <String>{},
    this.severityOverrides = const <String, RuleSeverity>{},
    this.groupModes = const <String, RuleMode>{},
    this.ruleModes = const <String, RuleMode>{},
    this.patternRules = const <PatternRule>[],
    this.structureSourceRoots = const <String>[],
    this.structureMaxTopLevelFiles = -1,
    this.structureAllowedTopLevel = const <String>[],
    this.structureRequiredDirectories = const <String>[],
    this.architectureLayers = const <String>[],
    this.architectureAllowedDependencies = const <String>[],
    this.architectureDeniedDependencies = const <String>[],
    this.architectureProfile = '',
    this.mvvmViews = const <String>[],
    this.mvvmViewModels = const <String>[],
    this.mvvmModels = const <String>[],
    this.mvvmRepositories = const <String>[],
    this.mvvmStrictViewModelBoundary = true,
  });

  final String root;

  /// Default language selection; `auto` enables all registered languages.
  final String language;

  /// Enabled language identifiers. An empty value uses [language].
  final List<String> languages;

  final List<String> includes;

  final List<String> excludes;

  final String changedBase;

  final bool changedLines;

  final List<String> entryPoints;

  final List<String> ignorePatterns;

  final List<String> classificationProduction;

  final List<String> classificationTest;

  final List<String> classificationGenerated;

  final int minDuplicationLines;

  final DuplicationMode duplicationMode;

  final int complexityThreshold;

  final int cognitiveThreshold;

  /// Maximum file line count; zero disables the limit.
  final int maxFileLines;

  /// Maximum function line count; zero disables the limit.
  final int maxFunctionLines;

  final bool csharpDeadCode;

  final String qualityProfile;

  final List<String> qualityGates;

  final Set<String> ruleGroups;

  /// Rule IDs explicitly disabled through `[severity]`.
  final Set<String> disabledRules;

  /// Per-rule severity settings. Absence means use rule metadata.
  final Map<String, RuleSeverity> severityOverrides;

  final Map<String, RuleMode> groupModes;

  final Map<String, RuleMode> ruleModes;

  final List<PatternRule> patternRules;

  final List<String> structureSourceRoots;

  /// Maximum allowed top-level source files; a negative value disables it.
  final int structureMaxTopLevelFiles;

  final List<String> structureAllowedTopLevel;

  final List<String> structureRequiredDirectories;

  final List<String> architectureLayers;

  /// Explicitly allowed cross-layer edges (`source -> target`).
  final List<String> architectureAllowedDependencies;

  /// Explicitly denied cross-layer edges (`source -> target`).
  final List<String> architectureDeniedDependencies;

  final String architectureProfile;

  final List<String> mvvmViews;

  final List<String> mvvmViewModels;

  final List<String> mvvmModels;

  final List<String> mvvmRepositories;

  final bool mvvmStrictViewModelBoundary;

  bool get dartMvvmEnabled => architectureProfile == 'dart-mvvm';

  AnalysisConfig copyWith({
    String? root,
    String? language,
    List<String>? languages,
    List<String>? includes,
    List<String>? excludes,
    List<String>? ignorePatterns,
    String? changedBase,
    bool? changedLines,
  }) => AnalysisConfig(
    root: root ?? this.root,
    language: language ?? this.language,
    languages: languages ?? this.languages,
    entryPoints: entryPoints,
    includes: includes ?? this.includes,
    excludes: excludes ?? this.excludes,
    changedBase: changedBase ?? this.changedBase,
    changedLines: changedLines ?? this.changedLines,
    ignorePatterns: ignorePatterns ?? this.ignorePatterns,
    classificationProduction: classificationProduction,
    classificationTest: classificationTest,
    classificationGenerated: classificationGenerated,
    minDuplicationLines: minDuplicationLines,
    duplicationMode: duplicationMode,
    complexityThreshold: complexityThreshold,
    cognitiveThreshold: cognitiveThreshold,
    maxFileLines: maxFileLines,
    maxFunctionLines: maxFunctionLines,
    csharpDeadCode: csharpDeadCode,
    qualityProfile: qualityProfile,
    qualityGates: qualityGates,
    ruleGroups: ruleGroups,
    disabledRules: disabledRules,
    severityOverrides: severityOverrides,
    groupModes: groupModes,
    ruleModes: ruleModes,
    patternRules: patternRules,
    structureSourceRoots: structureSourceRoots,
    structureMaxTopLevelFiles: structureMaxTopLevelFiles,
    structureAllowedTopLevel: structureAllowedTopLevel,
    structureRequiredDirectories: structureRequiredDirectories,
    architectureLayers: architectureLayers,
    architectureAllowedDependencies: architectureAllowedDependencies,
    architectureDeniedDependencies: architectureDeniedDependencies,
    architectureProfile: architectureProfile,
    mvvmViews: mvvmViews,
    mvvmViewModels: mvvmViewModels,
    mvvmModels: mvvmModels,
    mvvmRepositories: mvvmRepositories,
    mvvmStrictViewModelBoundary: mvvmStrictViewModelBoundary,
  );
}

enum RuleSemanticMaturity { text, token, ast, typeAware, project }

/// Review disposition for security-related rules.
enum SecurityFindingKind {
  /// Rule is not security-related.
  none,

  /// Potentially dangerous behavior requiring contextual review.
  hotspot,

  /// High-confidence security defect.
  vulnerability,
}

enum FindingTaxonomy {
  correctness,

  security,

  reliability,

  performance,

  design,

  architecture,

  maintainability,

  style,
}

enum RuleAnalysisRequirement {
  sourceText,

  tokens,

  ast,

  imports,

  declarations,

  functions,

  graph,

  types,
}

final class RuleMetadata {
  const RuleMetadata({
    required this.id,
    required this.defaultSeverity,
    required this.group,
    required this.title,
    required this.why,
    required this.suggestion,
    this.version = 1,
    this.semanticMaturity = RuleSemanticMaturity.text,
    this.requirements = const <RuleAnalysisRequirement>{
      RuleAnalysisRequirement.sourceText,
    },
    this.taxonomy = const <FindingTaxonomy>{},
    this.securityKind = SecurityFindingKind.none,
    this.languages = const <String>[],
    this.languageVersions = const <String, String>{},
    this.limitations = const <String>[],
  });

  final String id;

  final RuleSeverity defaultSeverity;

  final String group;

  final String title;

  final String why;

  final String suggestion;

  /// Behavior version used by triage and baseline migration.
  final int version;

  final RuleSemanticMaturity semanticMaturity;

  final Set<RuleAnalysisRequirement> requirements;

  /// Explicit concern taxonomy; empty derives a stable value from [group].
  final Set<FindingTaxonomy> taxonomy;

  final SecurityFindingKind securityKind;

  /// Effective security classification, conservatively treating unspecified
  /// security-group heuristics as review hotspots.
  SecurityFindingKind get effectiveSecurityKind =>
      securityKind != SecurityFindingKind.none
      ? securityKind
      : group == 'security'
      ? SecurityFindingKind.hotspot
      : SecurityFindingKind.none;

  Set<FindingTaxonomy> get effectiveTaxonomy => taxonomy.isNotEmpty
      ? taxonomy
      : <FindingTaxonomy>{
          switch (group) {
            'security' => FindingTaxonomy.security,
            'architecture' => FindingTaxonomy.architecture,
            'design' || 'yagni' => FindingTaxonomy.design,
            'style' || 'nim-style' => FindingTaxonomy.style,
            _ => FindingTaxonomy.maintainability,
          },
        };

  /// Explicit supported languages; empty means descriptor-derived applicability.
  final List<String> languages;

  final Map<String, String> languageVersions;

  /// Known precision or semantic limitations shown to users.
  final List<String> limitations;
}

final class CodeFlowStep {
  const CodeFlowStep({
    required this.path,
    required this.line,
    required this.message,
  });

  final String path;

  /// One-based source line.
  final int line;

  final String message;

  Map<String, Object> toJson() => <String, Object>{
    'path': path,
    'line': line,
    'message': message,
  };
}

final class Finding {
  const Finding({
    required this.code,
    required this.severity,
    required this.path,
    required this.line,
    this.endLine = 0,
    required this.message,
    this.confidence = '',
    this.why = '',
    this.suggestion = '',
    this.relatedFiles = const <String>[],
    this.snippet = '',
    this.codeFlow = const <CodeFlowStep>[],
  });

  final String code;

  final RuleSeverity severity;

  final String path;

  /// One-based start line.
  final int line;

  /// One-based inclusive end line; zero means [line].
  final int endLine;

  final String message;

  final String confidence;

  final String why;

  final String suggestion;

  final List<String> relatedFiles;

  final String snippet;

  final List<CodeFlowStep> codeFlow;

  Finding withSeverity(RuleSeverity severity) => Finding(
    code: code,
    severity: severity,
    path: path,
    line: line,
    endLine: endLine,
    message: message,
    confidence: confidence,
    why: why,
    suggestion: suggestion,
    relatedFiles: relatedFiles,
    snippet: snippet,
    codeFlow: codeFlow,
  );

  /// Legacy baseline key, intentionally excluding line numbers and severity.
  String get key => '$code|$path|$message';

  /// Legacy-compatible SHA-256 baseline fingerprint.
  String get fingerprint => sha256
      .convert(utf8.encode(key))
      .toString()
      .toUpperCase()
      .substring(0, 12);
}
