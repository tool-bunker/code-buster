use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::PreviewOptions;

pub enum UpdateOutcome {
    Success,
    Refused,
    Failed(u8),
}

enum UpdatePlan {
    LocalCargo { manifest: PathBuf },
    Unsupported,
}

pub fn execute(options: &PreviewOptions) -> Result<UpdateOutcome, String> {
    let plan = plan(Path::new(env!("CARGO_MANIFEST_DIR")));
    match plan {
        UpdatePlan::LocalCargo { manifest } => {
            println!("Reinstall the local Code Buster Rust checkout with Cargo");
            let arguments = [
                "install".to_owned(),
                "--path".to_owned(),
                manifest.to_string_lossy().into_owned(),
                "--force".to_owned(),
                "--locked".to_owned(),
            ];
            if options.dry_run {
                println!("Would run: cargo {}", arguments.join(" "));
                return Ok(UpdateOutcome::Success);
            }
            run("cargo", &arguments)
        }
        UpdatePlan::Unsupported => {
            println!(
                "No released cb update channel is configured; update the source checkout and reinstall with Cargo."
            );
            Ok(UpdateOutcome::Refused)
        }
    }
}

fn plan(manifest: &Path) -> UpdatePlan {
    if manifest.join("Cargo.toml").is_file() {
        UpdatePlan::LocalCargo {
            manifest: manifest.to_path_buf(),
        }
    } else {
        UpdatePlan::Unsupported
    }
}

fn run(executable: &str, arguments: &[String]) -> Result<UpdateOutcome, String> {
    let output = Command::new(executable)
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to run {executable}: {error}"))?;
    io::stdout()
        .write_all(&output.stdout)
        .map_err(|error| format!("failed to write update output: {error}"))?;
    io::stderr()
        .write_all(&output.stderr)
        .map_err(|error| format!("failed to write update error output: {error}"))?;
    let code = output.status.code().unwrap_or(2);
    if code == 0 {
        Ok(UpdateOutcome::Success)
    } else {
        Ok(UpdateOutcome::Failed(u8::try_from(code).unwrap_or(2)))
    }
}

#[cfg(test)]
mod tests {
    use super::{UpdatePlan, plan};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn local_cargo_plan_requires_the_source_manifest() {
        let root = tempdir().expect("temporary source directory must be created");
        assert!(matches!(plan(root.path()), UpdatePlan::Unsupported));
        fs::write(
            root.path().join("Cargo.toml"),
            b"[package]\nname = \"fixture\"\n",
        )
        .expect("fixture manifest must be written");
        assert!(matches!(
            plan(root.path()),
            UpdatePlan::LocalCargo { manifest } if manifest.as_path() == root.path()
        ));
    }
}
