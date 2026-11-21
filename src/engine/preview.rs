use serde::Serialize;

use crate::discovery::{
    GeneratedProvenance, PreparedPreview, ProcessingDiagnostic, SourceFile, prepare,
};
use crate::options::{PreviewOptions, ReportFormat};

pub fn execute(options: &PreviewOptions) -> Result<(), String> {
    if !matches!(options.format, ReportFormat::Text | ReportFormat::Json) {
        return Err("config --files supports text and json formats".to_owned());
    }
    let prepared = prepare(options)?;
    match options.format {
        ReportFormat::Json => print_json(options, &prepared),
        ReportFormat::Text => crate::report::write_report(options, |writer| {
            print_text(writer, &prepared, options.verbose)
        }),
        _ => unreachable!("unsupported format returned before preparation"),
    }
}

fn print_json(options: &PreviewOptions, prepared: &PreparedPreview) -> Result<(), String> {
    let report = PreviewReport {
        schema_version: 3,
        command: "config",
        view: "files",
        root: &prepared.root,
        files: &prepared.files,
        coverage: &prepared.coverage,
        language_versions: &prepared.language_versions,
        generated_provenance: (options.verbose && !prepared.generated_provenance.is_empty())
            .then_some(prepared.generated_provenance.as_slice()),
        processing_diagnostics: prepared.diagnostics.as_slice(),
    };
    let json = serde_json::to_string(&report)
        .map_err(|error| format!("failed to encode selected-files report: {error}"))?;
    crate::report::write_report(options, |writer| writeln!(writer, "{json}"))
}

fn print_text(
    writer: &mut dyn std::io::Write,
    prepared: &PreparedPreview,
    verbose: bool,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "Code Buster selected files: {} selected files",
        prepared.files.len()
    )?;
    if !prepared.coverage.is_empty() {
        let coverage = prepared
            .coverage
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(writer, "coverage: {coverage}")?;
    }
    for file in &prepared.files {
        writeln!(writer, "{}\t{}", file.language, file.path)?;
    }
    if verbose {
        for provenance in &prepared.generated_provenance {
            writeln!(
                writer,
                "generated\t{}\t{}\t{}",
                provenance.path, provenance.reason, provenance.source
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct PreviewReport<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    command: &'static str,
    view: &'static str,
    root: &'a str,
    files: &'a [SourceFile],
    coverage: &'a std::collections::BTreeMap<String, usize>,
    #[serde(
        rename = "languageVersions",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    language_versions: &'a std::collections::BTreeMap<String, String>,
    #[serde(
        rename = "generatedProvenance",
        skip_serializing_if = "Option::is_none"
    )]
    generated_provenance: Option<&'a [GeneratedProvenance]>,
    #[serde(
        rename = "processingDiagnostics",
        skip_serializing_if = "<[ProcessingDiagnostic]>::is_empty"
    )]
    processing_diagnostics: &'a [ProcessingDiagnostic],
}
