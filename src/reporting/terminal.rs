use std::env;
use std::ffi::OsStr;
use std::io::{self, IsTerminal};

pub(crate) fn colors_enabled() -> bool {
    io::stdout().is_terminal() && decorations_enabled()
}

pub(crate) fn interactive_progress_enabled() -> bool {
    io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && decorations_enabled()
        && env::var_os("CI").is_none()
}

fn decorations_enabled() -> bool {
    env::var_os("NO_COLOR").is_none()
        && env::var_os("TERM").is_none_or(|term| term != OsStr::new("dumb"))
}
