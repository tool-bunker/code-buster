use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    code_buster::run(env::args_os().skip(1))
}
