use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::cli::{PreviewOptions, ReportFormat};

use super::terminal;

const REVEAL_DELAY: Duration = Duration::from_millis(180);
const TICK_INTERVAL: Duration = Duration::from_millis(80);

pub(crate) struct AnalysisProgress {
    progress_bar: ProgressBar,
    cancel_reveal: Option<Sender<()>>,
    reveal: Option<JoinHandle<()>>,
}

impl AnalysisProgress {
    pub(crate) fn new(options: &PreviewOptions) -> Self {
        if !should_display(options, terminal::interactive_progress_enabled()) {
            return Self {
                progress_bar: ProgressBar::hidden(),
                cancel_reveal: None,
                reveal: None,
            };
        }

        let progress_bar = ProgressBar::hidden();
        let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);
        progress_bar.set_style(style);
        progress_bar.set_message("Discovering files…");

        let reveal_bar = progress_bar.clone();
        let (cancel_reveal, cancellation) = mpsc::channel();
        let reveal = thread::spawn(move || {
            if cancellation.recv_timeout(REVEAL_DELAY).is_err() {
                reveal_bar.set_draw_target(ProgressDrawTarget::stderr());
                reveal_bar.enable_steady_tick(TICK_INTERVAL);
                reveal_bar.tick();
            }
        });

        Self {
            progress_bar,
            cancel_reveal: Some(cancel_reveal),
            reveal: Some(reveal),
        }
    }

    pub(crate) fn set_phase(&self, phase: impl Into<String>) {
        self.progress_bar.set_message(phase.into());
    }

    pub(crate) fn finish(mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        if let Some(cancel_reveal) = self.cancel_reveal.take() {
            let _ = cancel_reveal.send(());
        }
        self.progress_bar.finish_and_clear();
        if let Some(reveal) = self.reveal.take() {
            let _ = reveal.join();
        }
    }
}

impl Drop for AnalysisProgress {
    fn drop(&mut self) {
        self.clear();
    }
}

fn should_display(options: &PreviewOptions, interactive_terminal: bool) -> bool {
    interactive_terminal
        && options.format == ReportFormat::Text
        && !options.ci
        && options.output.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_requires_interactive_human_output() {
        let options = PreviewOptions::default();
        assert!(should_display(&options, true));
        assert!(!should_display(&options, false));

        let mut machine = options.clone();
        machine.format = ReportFormat::Json;
        assert!(!should_display(&machine, true));

        let mut ci = options.clone();
        ci.ci = true;
        assert!(!should_display(&ci, true));

        let mut redirected = options;
        redirected.output = Some("report.txt".into());
        assert!(!should_display(&redirected, true));
    }
}
