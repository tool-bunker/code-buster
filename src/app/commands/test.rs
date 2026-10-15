use crate::cli::PreviewOptions;
use crate::summary_command;

pub enum TestOutcome {
    Success,
    Empty,
    Findings,
}

pub fn execute(options: &PreviewOptions) -> Result<TestOutcome, String> {
    let run = summary_command::analyze(options)?;
    if run.prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(TestOutcome::Empty);
    }
    println!("cb smoke test passed: {} files", run.prepared.files.len());
    if options.fail_on_issues && run.actionable_count > 0 {
        Ok(TestOutcome::Findings)
    } else {
        Ok(TestOutcome::Success)
    }
}
