use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use serde::Serialize;

use crate::cli::{PreviewOptions, ReportFormat};
use crate::discovery::prepare;

pub enum HotspotsOutcome {
    Success,
    Empty,
}

#[derive(Clone, Debug, Serialize)]
struct Hotspot {
    path: String,
    commits: usize,
    added: usize,
    deleted: usize,
    churn: usize,
    risk: f64,
}

#[derive(Default)]
struct HotspotTotals {
    commits: usize,
    added: usize,
    deleted: usize,
}

#[derive(Serialize)]
struct HotspotsReport<'a> {
    version: u8,
    command: &'static str,
    view: &'static str,
    root: &'a str,
    hotspots: &'a [Hotspot],
}

pub fn execute(options: &PreviewOptions) -> Result<HotspotsOutcome, String> {
    let prepared = prepare(options)?;
    if prepared.files.is_empty() && !options.allow_empty {
        eprintln!("no source files found (use --allow-empty to allow this)");
        return Ok(HotspotsOutcome::Empty);
    }

    let allowed = prepared.sources.keys().cloned().collect::<BTreeSet<_>>();
    let mut hotspots = from_git(&prepared.root, &allowed);
    if options.top > 0 && hotspots.len() > options.top as usize {
        hotspots.truncate(options.top as usize);
    }

    if matches!(options.format, ReportFormat::Json) {
        let output = serde_json::to_string(&HotspotsReport {
            version: 1,
            command: "quality",
            view: "hotspots",
            root: &prepared.root,
            hotspots: &hotspots,
        })
        .map_err(|error| format!("failed to encode hotspots report: {error}"))?;
        println!("{output}");
    } else {
        print_text(&hotspots);
    }
    Ok(HotspotsOutcome::Success)
}

fn from_git(root: &str, allowed: &BTreeSet<String>) -> Vec<Hotspot> {
    let Ok(output) = Command::new("git")
        .args([
            "-C",
            root,
            "log",
            "--no-merges",
            "--numstat",
            "--format=format:__CODE_BUSTER_COMMIT__",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    parse_numstat(&String::from_utf8_lossy(&output.stdout), allowed)
}

fn parse_numstat(text: &str, allowed: &BTreeSet<String>) -> Vec<Hotspot> {
    let mut totals = BTreeMap::<String, HotspotTotals>::new();
    let mut touched = BTreeSet::<String>::new();

    for line in text.split('\n') {
        if line.trim() == "__CODE_BUSTER_COMMIT__" {
            finish_commit(&mut totals, &mut touched);
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] == "-" || fields[1] == "-" {
            continue;
        }
        let path = fields[2].replace('\\', "/");
        if !allowed.is_empty() && !allowed.contains(&path) {
            continue;
        }
        let (Ok(added), Ok(deleted)) = (fields[0].parse::<usize>(), fields[1].parse::<usize>())
        else {
            continue;
        };
        let total = totals.entry(path.clone()).or_default();
        total.added += added;
        total.deleted += deleted;
        touched.insert(path);
    }
    finish_commit(&mut totals, &mut touched);

    let mut hotspots = totals
        .into_iter()
        .map(|(path, total)| {
            let churn = total.added + total.deleted;
            Hotspot {
                path,
                commits: total.commits,
                added: total.added,
                deleted: total.deleted,
                churn,
                risk: churn as f64 * (1.0 + (1.0 + total.commits as f64).ln()),
            }
        })
        .collect::<Vec<_>>();
    hotspots.sort_by(|left, right| {
        right
            .risk
            .total_cmp(&left.risk)
            .then_with(|| left.path.cmp(&right.path))
    });
    hotspots
}

fn finish_commit(totals: &mut BTreeMap<String, HotspotTotals>, touched: &mut BTreeSet<String>) {
    for path in touched.iter() {
        totals.entry(path.clone()).or_default().commits += 1;
    }
    touched.clear();
}

fn print_text(hotspots: &[Hotspot]) {
    println!("Code Buster hotspots: {}", hotspots.len());
    if hotspots.is_empty() {
        println!("No Git history available for discovered files.");
    }
    for hotspot in hotspots {
        println!(
            "{} — risk {:.1}, churn {}, commits {} (+{}/-{})",
            hotspot.path,
            hotspot.risk,
            hotspot.churn,
            hotspot.commits,
            hotspot.added,
            hotspot.deleted
        );
    }
}
