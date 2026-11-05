use std::fs;

use crate::cli::InitOptions;
use crate::config::starter_config;

pub enum InitOutcome {
    Created,
    Exists,
}

pub fn execute(options: &InitOptions) -> Result<InitOutcome, String> {
    let root = options.target.as_ref().unwrap_or(&options.root);
    let path = root.join("code-buster.toml");
    if path.exists() && !options.force {
        eprintln!("config exists (use --force)");
        return Ok(InitOutcome::Exists);
    }
    fs::write(&path, starter_config(options.profile.as_deref()))
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    println!("created {}", path.display());
    Ok(InitOutcome::Created)
}
