/// Stable extension API for the Code Buster analysis engine.
///
/// Concrete adapters, pipeline stages, caches, CLI commands, and generated
/// parity data are implementation details and intentionally not exported.
library;

export 'src/catalog/rule_catalog.dart' show RuleCatalog;
export 'src/cli/cli_contract.dart'
    show CodeBusterCliContract, CodeBusterCliOptions, CodeBusterCommand;
export 'src/core/models.dart'
    show
        AnalysisConfig,
        CodeFlowStep,
        DuplicationMode,
        Finding,
        FindingTaxonomy,
        PatternRule,
        RuleAnalysisRequirement,
        RuleMetadata,
        RuleSemanticMaturity,
        RuleSeverity,
        SecurityFindingKind;
export 'src/core/processing_diagnostic.dart'
    show ProcessingDiagnostic, ProcessingDiagnosticSeverity;
export 'src/core/rule.dart'
    show
        CodeBusterRule,
        RuleContext,
        RuleRegistry,
        SelfContainedRule,
        SemanticRule,
        SourcePatternRule;
export 'src/core/run_manifest.dart' show RunManifest, RunStatus;
export 'src/discovery/discovery.dart' show ChangedLineRange, SourceFile;
export 'src/engine/analysis.dart' show FunctionSource;
export 'src/engine/analysis_runner.dart' show AnalysisRun, AnalysisRunner;
export 'src/graph/graph.dart' show DependencyGraph, GraphAnalysis;
export 'src/plugins/language_plugin.dart'
    show
        BuiltInLanguagePlugin,
        FindingOrderLanguagePlugin,
        LanguageAnalysis,
        LanguagePlugin,
        LanguagePluginRegistry;
export 'src/reporting/reporting.dart' show FindingReporter, ReportFormat;
