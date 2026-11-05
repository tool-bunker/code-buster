use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::options::PreviewOptions;

#[cfg(not(windows))]
const INSTALLER_URL: &str = "https://toolbunker.dev/codebuster/install";
#[cfg(windows)]
const WINDOWS_INSTALLER_URL: &str = "https://toolbunker.dev/codebuster/install.ps1";
const INSTALL_MARKER: &str = "share/code-buster/install.toml";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateOutcome {
    Success,
    Refused,
    Failed(u8),
}

#[derive(Debug, Eq, PartialEq)]
enum UpdatePlan {
    Homebrew,
    CargoRegistry,
    LocalCargo { manifest: PathBuf },
    NativeInstaller { prefix: PathBuf },
    Unsupported,
}

struct UpdateContext {
    executable: PathBuf,
    manifest: PathBuf,
    cargo_home: Option<PathBuf>,
    home: Option<PathBuf>,
}

struct UpdateCommand {
    executable: &'static str,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl UpdateCommand {
    fn new(executable: &'static str, arguments: Vec<OsString>) -> Self {
        Self {
            executable,
            arguments,
            environment: Vec::new(),
        }
    }

    #[cfg(not(windows))]
    fn with_environment(mut self, key: &str, value: &OsStr) -> Self {
        self.environment
            .push((OsString::from(key), value.to_os_string()));
        self
    }

    fn display(&self) -> String {
        self.environment
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}={}",
                    key.to_string_lossy(),
                    display_word(value.as_os_str())
                )
            })
            .chain(std::iter::once(self.executable.to_owned()))
            .chain(
                self.arguments
                    .iter()
                    .map(|argument| display_word(argument.as_os_str())),
            )
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn execute(options: &PreviewOptions) -> Result<UpdateOutcome, String> {
    let home = home_directory();
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".cargo")));
    let context = UpdateContext {
        executable: env::current_exe()
            .map_err(|error| format!("failed to locate the running cb executable: {error}"))?,
        manifest: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        cargo_home,
        home,
    };
    execute_plan(plan(&context), options.dry_run)
}

fn execute_plan(plan: UpdatePlan, dry_run: bool) -> Result<UpdateOutcome, String> {
    match plan {
        UpdatePlan::Homebrew => {
            println!("Update Code Buster with Homebrew");
            run_commands(
                &[
                    UpdateCommand::new("brew", strings(&["update"])),
                    UpdateCommand::new("brew", strings(&["upgrade", "code-buster"])),
                ],
                dry_run,
            )
        }
        UpdatePlan::CargoRegistry => {
            println!("Update Code Buster from crates.io with Cargo");
            run_commands(
                &[UpdateCommand::new(
                    "cargo",
                    strings(&["install", "code-buster", "--locked", "--force"]),
                )],
                dry_run,
            )
        }
        UpdatePlan::LocalCargo { manifest } => {
            println!("Reinstall the local Code Buster checkout with Cargo");
            run_commands(
                &[UpdateCommand::new(
                    "cargo",
                    vec![
                        OsString::from("install"),
                        OsString::from("--path"),
                        manifest.into_os_string(),
                        OsString::from("--force"),
                        OsString::from("--locked"),
                    ],
                )],
                dry_run,
            )
        }
        UpdatePlan::NativeInstaller { prefix } => {
            println!("Update Code Buster with the verified native installer");
            execute_native_installer(&prefix, dry_run)
        }
        UpdatePlan::Unsupported => {
            eprintln!(
                "Could not identify how this cb executable was installed. Reinstall it with Homebrew, Cargo, or the verified native installer."
            );
            Ok(UpdateOutcome::Refused)
        }
    }
}

fn plan(context: &UpdateContext) -> UpdatePlan {
    let executable = canonical_or_original(&context.executable);
    if is_homebrew_executable(&executable) {
        return UpdatePlan::Homebrew;
    }

    if let Some(cargo_home) = &context.cargo_home
        && paths_equal(
            executable.parent().unwrap_or_else(|| Path::new("")),
            &cargo_home.join("bin"),
        )
    {
        if cargo_install_is_local(cargo_home) && context.manifest.join("Cargo.toml").is_file() {
            return UpdatePlan::LocalCargo {
                manifest: context.manifest.clone(),
            };
        }
        return UpdatePlan::CargoRegistry;
    }

    if let Some(prefix) = native_install_prefix(&executable, context.home.as_deref()) {
        return UpdatePlan::NativeInstaller { prefix };
    }

    if context.manifest.join("Cargo.toml").is_file() && !is_cargo_registry_source(&context.manifest)
    {
        return UpdatePlan::LocalCargo {
            manifest: context.manifest.clone(),
        };
    }

    UpdatePlan::Unsupported
}

fn is_homebrew_executable(executable: &Path) -> bool {
    let path = executable.to_string_lossy().replace('\\', "/");
    path.contains("/Cellar/code-buster/")
}

fn cargo_install_is_local(cargo_home: &Path) -> bool {
    let Ok(bytes) = fs::read(cargo_home.join(".crates2.json")) else {
        return false;
    };
    let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    metadata
        .get("installs")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|installs| {
            installs.iter().any(|(package, details)| {
                package.starts_with("code-buster ")
                    && package.contains("(path+")
                    && details
                        .get("bins")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|bins| bins.iter().any(|bin| bin == "cb"))
            })
        })
}

fn native_install_prefix(executable: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let prefix = executable.parent()?.parent()?;
    let marker = prefix.join(INSTALL_MARKER);
    if fs::read_to_string(marker).is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.trim() == "channel = \"native\"")
    }) {
        return Some(prefix.to_path_buf());
    }

    let home = home?;
    let executable_name = if cfg!(windows) { "cb.exe" } else { "cb" };
    paths_equal(
        executable,
        &home.join(".local").join("bin").join(executable_name),
    )
    .then(|| home.join(".local"))
}

fn is_cargo_registry_source(manifest: &Path) -> bool {
    manifest
        .to_string_lossy()
        .replace('\\', "/")
        .contains("/registry/src/")
}

fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    canonical_or_original(left) == canonical_or_original(right)
}

fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn run_commands(commands: &[UpdateCommand], dry_run: bool) -> Result<UpdateOutcome, String> {
    for command in commands {
        if dry_run {
            println!("Would run: {}", command.display());
            continue;
        }
        let outcome = run(command)?;
        if outcome != UpdateOutcome::Success {
            return Ok(outcome);
        }
    }
    Ok(UpdateOutcome::Success)
}

fn run(command: &UpdateCommand) -> Result<UpdateOutcome, String> {
    let output = Command::new(command.executable)
        .args(&command.arguments)
        .envs(command.environment.iter().cloned())
        .output()
        .map_err(|error| format!("failed to run {}: {error}", command.executable))?;
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

#[cfg(not(windows))]
fn execute_native_installer(prefix: &Path, dry_run: bool) -> Result<UpdateOutcome, String> {
    run_commands(
        &[UpdateCommand::new(
            "sh",
            vec![
                OsString::from("-c"),
                OsString::from(format!("curl -fsSL {INSTALLER_URL} | sh")),
            ],
        )
        .with_environment("PREFIX", prefix.as_os_str())],
        dry_run,
    )
}

#[cfg(windows)]
fn execute_native_installer(prefix: &Path, dry_run: bool) -> Result<UpdateOutcome, String> {
    let escaped_prefix = prefix.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$parent = Get-Process -Id {} -ErrorAction SilentlyContinue; \
         if ($parent) {{ $parent.WaitForExit() }}; \
         $env:PREFIX = '{escaped_prefix}'; \
         $installer = Join-Path $env:TEMP ('code-buster-update-' + [guid]::NewGuid() + '.ps1'); \
         Invoke-WebRequest -Uri '{WINDOWS_INSTALLER_URL}' -OutFile $installer; \
         try {{ & $installer }} finally {{ Remove-Item -Force -ErrorAction SilentlyContinue $installer }}",
        std::process::id()
    );
    let command = UpdateCommand::new(
        "powershell.exe",
        vec![
            OsString::from("-NoProfile"),
            OsString::from("-ExecutionPolicy"),
            OsString::from("Bypass"),
            OsString::from("-Command"),
            OsString::from(script),
        ],
    );
    if dry_run {
        println!("Would schedule after cb exits: {}", command.display());
        return Ok(UpdateOutcome::Success);
    }
    Command::new(command.executable)
        .args(&command.arguments)
        .spawn()
        .map_err(|error| format!("failed to schedule the Windows update: {error}"))?;
    println!("The update was scheduled and will finish after this cb process exits.");
    Ok(UpdateOutcome::Success)
}

fn display_word(word: &OsStr) -> String {
    let value = word.to_string_lossy();
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:".contains(&byte))
    {
        return value.into_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::{UpdateContext, UpdatePlan, plan};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn context(executable: PathBuf, root: &Path) -> UpdateContext {
        UpdateContext {
            executable,
            manifest: root.join("checkout"),
            cargo_home: Some(root.join("cargo")),
            home: Some(root.join("home")),
        }
    }

    #[test]
    fn detects_homebrew_before_other_channels() {
        let root = tempdir().expect("temporary directory must be created");
        let executable = root.path().join("Cellar/code-buster/0.13.0/bin/cb");
        assert_eq!(
            plan(&context(executable, root.path())),
            UpdatePlan::Homebrew
        );
    }

    #[test]
    fn detects_registry_and_local_cargo_installs() {
        let root = tempdir().expect("temporary directory must be created");
        let cargo_home = root.path().join("cargo");
        fs::create_dir_all(cargo_home.join("bin")).expect("Cargo bin directory must be created");
        let executable = cargo_home.join("bin/cb");
        let registry_context = context(executable.clone(), root.path());
        assert_eq!(plan(&registry_context), UpdatePlan::CargoRegistry);

        fs::create_dir_all(root.path().join("checkout"))
            .expect("checkout directory must be created");
        fs::write(
            root.path().join("checkout/Cargo.toml"),
            b"[package]\nname = \"code-buster\"\n",
        )
        .expect("checkout manifest must be written");
        fs::write(
            cargo_home.join(".crates2.json"),
            br#"{"installs":{"code-buster 0.13.0 (path+file:///tmp/code-buster)":{"bins":["cb"]}}}"#,
        )
        .expect("Cargo install metadata must be written");
        assert_eq!(
            plan(&context(executable, root.path())),
            UpdatePlan::LocalCargo {
                manifest: root.path().join("checkout")
            }
        );
    }

    #[test]
    fn detects_native_installs_with_marker_or_default_prefix() {
        let root = tempdir().expect("temporary directory must be created");
        let prefix = root.path().join("custom");
        fs::create_dir_all(prefix.join("share/code-buster"))
            .expect("marker directory must be created");
        fs::write(
            prefix.join("share/code-buster/install.toml"),
            b"channel = \"native\"\n",
        )
        .expect("native marker must be written");
        assert_eq!(
            plan(&context(prefix.join("bin/cb"), root.path())),
            UpdatePlan::NativeInstaller {
                prefix: prefix.clone()
            }
        );

        let mut default_context = context(root.path().join("home/.local/bin/cb"), root.path());
        default_context.home = Some(root.path().join("home"));
        assert_eq!(
            plan(&default_context),
            UpdatePlan::NativeInstaller {
                prefix: root.path().join("home/.local")
            }
        );
    }

    #[test]
    fn falls_back_to_a_real_local_checkout_and_rejects_unknown_binaries() {
        let root = tempdir().expect("temporary directory must be created");
        let mut local = context(root.path().join("target/debug/cb"), root.path());
        fs::create_dir_all(&local.manifest).expect("checkout directory must be created");
        fs::write(
            local.manifest.join("Cargo.toml"),
            b"[package]\nname = \"code-buster\"\n",
        )
        .expect("checkout manifest must be written");
        assert_eq!(
            plan(&local),
            UpdatePlan::LocalCargo {
                manifest: local.manifest.clone()
            }
        );

        local.manifest = root.path().join("missing");
        assert_eq!(plan(&local), UpdatePlan::Unsupported);
    }
}
