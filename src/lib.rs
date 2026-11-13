//! Code Buster is a repository-aware static analyzer for AI-assisted development.
//!
//! Most users should install and run the `cb` command-line application:
//!
//! ```text
//! cargo install code-buster --locked
//! cb summary
//! ```
//!
//! See the [Code Buster documentation](https://toolbunker.dev/codebuster/docs/)
//! for installation, configuration, commands, and rule documentation.

#![warn(missing_docs)]

mod app;
mod engine;
mod graph;
mod languages;
mod model;
mod reporting;
mod rules;

use app::cli;
use app::commands::{
    baseline as baseline_command, completions as completions_command,
    complexity as complexity_command, config as config_command, dead as dead_command,
    doctor as doctor_command, duplication as duplication_command, explain as explain_command,
    fix as fix_command, graph as graph_command, hotspots as hotspots_command, init as init_command,
    quality as quality_command, repository_view as repository_view_command, rules as rules_command,
    structure as structure_command, summary as summary_command, update as update_command,
    workflow as workflow_command,
};
use engine::{
    analysis_cache, analysis_engine, discovery, finding_controls, preview, repository_defaults,
    semantic_diff, source_analysis_context,
};
use graph::{
    architecture as architecture_graph, dead_analysis, dependency as dependency_graph,
    export_analysis,
};
use languages::{
    cpp::rules as cpp_rules,
    csharp::rules as csharp_rules,
    css::rules as css_rules,
    dart::{
        analyzer_config as dart_analyzer_config, core as dart_core_rules,
        flutter_build as dart_flutter_build, lifecycle as dart_lifecycle,
        model_contracts as dart_model_contracts, model_duplication as dart_model_duplication,
        mvvm as dart_mvvm_rules, null_assertion as dart_null_assertion, oop as dart_oop_rules,
        package_cycle as dart_package_cycle, performance as dart_performance,
        reliability as dart_reliability, security as dart_security,
    },
    functions as function_sources,
    go::rules as go_rules,
    html::rules as html_rules,
    java::rules as java_rules,
    lua::rules as lua_rules,
    mojo::rules as mojo_rules,
    nim::rules as nim_rules,
    python::rules as python_rules,
    rust::rules as rust_rules,
    shell::rules as shell_rules,
    sql::rules as sql_rules,
    typescript::rules as typescript_rules,
    wren::rules as wren_rules,
};
use model::{config, findings, options};
use reporting::{report, sarif_ingestion};
use rules::{
    advanced_duplication, ai_security as ai_security_rules, cargo as cargo_rules,
    catalog as rule_catalog, clean_code as clean_code_rules, complexity, constant_arguments,
    diff_quality as diff_quality_rules, duplication, feature_flags,
    frameworks::{
        bevy as bevy_rules, fastapi as fastapi_rules, flutter as flutter_quality_rules,
        pixijs as pixijs_rules, svelte as svelte_rules,
    },
    generated_code_risks, generic as generic_rules, github_actions as github_actions_rules,
    layout as layout_rules, object_soup as object_soup_rules, oop as oop_rules,
    pattern as pattern_rules, regex as regex_rules,
    repository_contracts as repository_contract_rules,
    repository_policy as repository_policy_rules, runtime_bootstrap as runtime_bootstrap_rule,
    sql_inline as sql_inline_rule, structure, trivial_wrappers, ui_consistency,
    yagni as yagni_rules, yagni_call_index, yagni_concentration,
};

use std::ffi::OsString;
use std::process::ExitCode;

/// Runs Code Buster with the supplied command-line arguments.
///
/// The arguments must not include the executable name. The returned exit code
/// is the status produced by the selected Code Buster command.
///
/// Most applications should invoke the installed `cb` executable instead of
/// using this library entry point directly.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let command = match cli::parse(arguments) {
        Ok(command) => command,
        Err(error) => {
            if error.starts_with("Unknown Code Buster command:")
                || error == "--no-cache cannot be combined with --cache-dir"
            {
                eprintln!("{error}\n{}", cli::argument_usage());
            } else {
                eprintln!("{error}");
            }
            return ExitCode::from(2);
        }
    };
    execute_command(command).unwrap_or_else(error_exit)
}

fn execute_command(command: cli::Command) -> Result<ExitCode, String> {
    Ok(match command {
        cli::Command::Help => {
            println!("{}", cli::usage(reporting::terminal::colors_enabled()));
            ExitCode::SUCCESS
        }
        cli::Command::Version => {
            println!("cb {}", env!("CARGO_PKG_VERSION"));
            println!("runtime: Rust");
            ExitCode::SUCCESS
        }
        cli::Command::Summary(options) => summary_exit(summary_command::execute(&options)),
        cli::Command::Baseline(options) => match baseline_command::execute(&options)? {
            baseline_command::BaselineOutcome::Success => ExitCode::SUCCESS,
            baseline_command::BaselineOutcome::Empty => ExitCode::from(1),
        },
        cli::Command::Fix(options) => match fix_command::execute(&options)? {
            fix_command::FixOutcome::Success => ExitCode::SUCCESS,
            fix_command::FixOutcome::Empty => ExitCode::from(1),
        },
        cli::Command::Quality(options, view) => quality_exit(&options, view)?,
        cli::Command::Review(options, view) => review_exit(&options, view),
        cli::Command::Update(options) => match update_command::execute(&options)? {
            update_command::UpdateOutcome::Success => ExitCode::SUCCESS,
            update_command::UpdateOutcome::Refused => ExitCode::from(2),
            update_command::UpdateOutcome::Failed(code) => ExitCode::from(code),
        },
        cli::Command::ConfigFiles(options) => {
            preview::execute(&options)?;
            ExitCode::SUCCESS
        }
        cli::Command::Completions(shell) => {
            completions_command::execute(&shell);
            ExitCode::SUCCESS
        }
        cli::Command::Dead(options) => match dead_command::execute(&options)? {
            dead_command::DeadOutcome::Success => ExitCode::SUCCESS,
            dead_command::DeadOutcome::Empty => ExitCode::from(1),
            dead_command::DeadOutcome::Findings => ExitCode::from(2),
        },
        cli::Command::Graph(options) => match graph_command::execute(&options)? {
            graph_command::GraphOutcome::Success => ExitCode::SUCCESS,
            graph_command::GraphOutcome::Empty => ExitCode::from(1),
        },
        cli::Command::Rules(options) => {
            if options.targets.is_empty() {
                rules_command::execute(&options.common)?;
                ExitCode::SUCCESS
            } else {
                repository_view_exit(Ok(explain_command::execute(&options)))
            }
        }
        cli::Command::Inspect(options, view) => match view {
            cli::InspectView::Details => {
                repository_view_exit(repository_view_command::execute_inspect(&options))
            }
            cli::InspectView::Related => {
                repository_view_exit(repository_view_command::execute_related(&options))
            }
            cli::InspectView::Why => {
                repository_view_exit(repository_view_command::execute_why(&options))
            }
            cli::InspectView::Path => {
                repository_view_exit(repository_view_command::execute_path(&options))
            }
        },
        cli::Command::Config(options) => {
            config_command::execute(&options)?;
            ExitCode::SUCCESS
        }
        cli::Command::Doctor(options) => {
            doctor_command::execute(&options)?;
            ExitCode::SUCCESS
        }
        cli::Command::Duplication(options) => {
            duplication_exit(duplication_command::execute(&options))
        }
        cli::Command::Init(options) => match init_command::execute(&options)? {
            init_command::InitOutcome::Created => ExitCode::SUCCESS,
            init_command::InitOutcome::Exists => ExitCode::from(1),
        },
    })
}

fn review_exit(options: &options::PreviewOptions, view: cli::ReviewView) -> ExitCode {
    match view {
        cli::ReviewView::Findings => {
            summary_exit(summary_command::execute_report(options, "review"))
        }
        cli::ReviewView::Plan => unit_exit(workflow_command::execute_plan(options)),
        cli::ReviewView::Actions => match workflow_command::execute_actions(options) {
            Ok(workflow_command::WorkflowOutcome::Success) => ExitCode::SUCCESS,
            Ok(workflow_command::WorkflowOutcome::Findings) => ExitCode::from(2),
            Err(error) => error_exit(error),
        },
    }
}

fn quality_exit(
    options: &options::PreviewOptions,
    view: cli::QualityView,
) -> Result<ExitCode, String> {
    Ok(match view {
        cli::QualityView::Overview => match quality_command::execute_quality(options)? {
            quality_command::QualityOutcome::Success => ExitCode::SUCCESS,
            quality_command::QualityOutcome::Findings => ExitCode::from(2),
        },
        cli::QualityView::Score => {
            quality_command::execute_score(options)?;
            ExitCode::SUCCESS
        }
        cli::QualityView::Complexity => match complexity_command::execute(options)? {
            complexity_command::ComplexityOutcome::Success => ExitCode::SUCCESS,
            complexity_command::ComplexityOutcome::Empty => ExitCode::from(1),
            complexity_command::ComplexityOutcome::Findings => ExitCode::from(2),
        },
        cli::QualityView::Hotspots => match hotspots_command::execute(options)? {
            hotspots_command::HotspotsOutcome::Success => ExitCode::SUCCESS,
            hotspots_command::HotspotsOutcome::Empty => ExitCode::from(1),
        },
        cli::QualityView::Structure => match structure_command::execute(options)? {
            structure_command::StructureOutcome::Success => ExitCode::SUCCESS,
            structure_command::StructureOutcome::Empty => ExitCode::from(1),
            structure_command::StructureOutcome::Findings => ExitCode::from(2),
        },
    })
}

fn duplication_exit(result: Result<duplication_command::DuplicationOutcome, String>) -> ExitCode {
    match result {
        Ok(duplication_command::DuplicationOutcome::Success) => ExitCode::SUCCESS,
        Ok(duplication_command::DuplicationOutcome::Empty) => ExitCode::from(1),
        Ok(duplication_command::DuplicationOutcome::Findings) => ExitCode::from(2),
        Err(error) => error_exit(error),
    }
}

fn unit_exit(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => error_exit(error),
    }
}

fn error_exit(error: String) -> ExitCode {
    eprintln!("{error}");
    ExitCode::from(2)
}

fn summary_exit(result: Result<summary_command::SummaryOutcome, String>) -> ExitCode {
    match result {
        Ok(summary_command::SummaryOutcome::Success) => ExitCode::SUCCESS,
        Ok(summary_command::SummaryOutcome::Empty) => ExitCode::from(1),
        Ok(summary_command::SummaryOutcome::Findings) => ExitCode::from(2),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn repository_view_exit(
    result: Result<repository_view_command::RepositoryViewOutcome, String>,
) -> ExitCode {
    match result {
        Ok(repository_view_command::RepositoryViewOutcome::Success) => ExitCode::SUCCESS,
        Ok(repository_view_command::RepositoryViewOutcome::Findings) => ExitCode::from(2),
        Ok(repository_view_command::RepositoryViewOutcome::NotFound) => ExitCode::from(1),
        Ok(repository_view_command::RepositoryViewOutcome::Usage) => ExitCode::from(64),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
