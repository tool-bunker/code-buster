use std::fs;

use crate::cli::InitOptions;
use crate::config::STARTER_CONFIG;

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
    fs::write(&path, STARTER_CONFIG)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    println!("created {}", path.display());
    Ok(InitOutcome::Created)
}
