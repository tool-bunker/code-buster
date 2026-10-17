use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cb"))
        .args(arguments)
        .output()
        .expect("cb must execute")
}

fn run_root_command(command: &str, root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cb"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cb {command} must execute: {error}"))
}

fn run_root_view(command: &str, root: &Path, view: &[&str], arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cb"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(view)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cb {command} must execute: {error}"))
}

fn run_summary(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("summary", root, arguments)
}

fn run_preview(root: &Path, arguments: &[&str]) -> Output {
    run_root_view("config", root, &["--files"], arguments)
}

fn run_config(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("config", root, arguments)
}

fn run_doctor(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("doctor", root, arguments)
}

fn run_structure(root: &Path, arguments: &[&str]) -> Output {
    run_root_view("quality", root, &["--structure"], arguments)
}

fn run_duplication(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("duplication", root, arguments)
}

fn run_complexity(root: &Path, arguments: &[&str]) -> Output {
    run_root_view("quality", root, &["--complexity"], arguments)
}

fn run_flags(root: &Path, arguments: &[&str]) -> Output {
    run_root_view(
        "review",
        root,
        &["--only", "feature-flag", "--advisory"],
        arguments,
    )
}

fn run_graph(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("graph", root, arguments)
}

fn run_dead(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("dead", root, arguments)
}

fn run_hotspots(root: &Path, arguments: &[&str]) -> Output {
    run_root_view("quality", root, &["--hotspots"], arguments)
}

fn run_repository_view(command: &str, root: &Path, arguments: &[&str]) -> Output {
    match command {
        "related" => run_root_view("inspect", root, &["--related"], arguments),
        "why" => run_root_view("inspect", root, &["--why"], arguments),
        "path" => run_root_view("inspect", root, &["--path"], arguments),
        _ => run_root_command(command, root, arguments),
    }
}

fn run_rules(root: &Path, arguments: &[&str]) -> Output {
    run_root_command("rules", root, arguments)
}

fn run_explain(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cb"))
        .arg("rules")
        .args(arguments)
        .output()
        .expect("cb rules must execute")
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git must execute");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn preview_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/preview")
}

mod core_commands {
    use super::*;

    include!("cli/core.rs");
}

mod analysis_commands {
    use super::*;

    include!("cli/analysis.rs");
}

mod workflow_commands {
    use super::*;

    include!("cli/workflows.rs");
}

mod language_rules {
    use super::*;

    include!("cli/languages.rs");
}

struct TempDirectory {
    path: PathBuf,
    _guard: TempDir,
}

impl TempDirectory {
    fn new(prefix: &str) -> Self {
        let guard = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("temporary directory must be created");
        let path = guard.path().to_path_buf();
        Self {
            path,
            _guard: guard,
        }
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent must be created");
        }
        fs::write(path, bytes).expect("fixture must be written");
    }
}
