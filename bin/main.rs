//! Command-line certificate inspection and format conversion. I/O stays here.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
mod encoding;
mod report;
mod schema;
use std::{
    io::{Read, Write},
    path::PathBuf,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use clap::{CommandFactory, Parser, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    /// One compact JSON report followed by a newline.
    Jsonl,
    Yaml,
    #[value(alias = "msgpack")]
    Messagepack,
    Cbor,
    Toml,
    Der,
    Pem,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum InputFormat {
    Auto,
    Der,
    Pem,
}

/// Inspect one certificate or convert its encoding without trust or validity verification.
#[derive(Parser)]
#[command(
    version,
    about = "Inspect one certificate or convert its encoding without trust or validity verification",
    after_help = "Reports include parsed fields and decoding diagnostics. DER/PEM conversion preserves the original DER. TOML omits absent fields and represents unsigned integers above i64::MAX as decimal strings."
)]
struct Args {
    /// Certificate path; omit or use - to read stdin.
    #[arg(value_name = "INPUT")]
    input: Option<PathBuf>,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,
    /// Output path; omit or use - to write stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Input encoding.
    #[arg(long, value_enum, default_value = "auto")]
    input_format: InputFormat,
    /// Omit duplicate DER/raw buffers from reports; retain parsed fields.
    #[arg(long)]
    summary: bool,
    /// Print the JSON Schema for full reports (or --summary), without reading a certificate.
    #[arg(long, conflicts_with_all = ["input", "input_format", "max_input_bytes", "format"])]
    schema: bool,
    /// Maximum encoded input size in bytes.
    #[arg(long, default_value = "1048576")]
    max_input_bytes: std::num::NonZeroUsize,
}

fn run(args: Args) -> Result<()> {
    let Args {
        input,
        output,
        format,
        input_format,
        summary,
        max_input_bytes: limit,
        schema,
    } = args;
    if schema {
        let mut bytes = serde_json::to_vec_pretty(&schema::generate(summary)?)?;
        bytes.push(b'\n');
        return write_output(output, bytes);
    }
    let limit = limit.get();
    let read_limit = u64::try_from(limit)?
        .checked_add(1)
        .ok_or("invalid input limit")?;
    let mut input_bytes = Vec::new();
    match input.as_deref().filter(|p| *p != std::path::Path::new("-")) {
        Some(path) => std::fs::File::open(path)?
            .take(read_limit)
            .read_to_end(&mut input_bytes)?,
        None => std::io::stdin()
            .lock()
            .take(read_limit)
            .read_to_end(&mut input_bytes)?,
    };
    let options = x509_info::ParseOptions {
        max_input_bytes: limit,
    };
    let is_pem = input_format == InputFormat::Pem
        || (input_format == InputFormat::Auto
            && input_bytes.trim_ascii().starts_with(b"-----BEGIN "));
    let info = if is_pem {
        x509_info::parse_pem(&input_bytes, options)?
    } else {
        x509_info::parse_der(&input_bytes, options)?
    };
    drop(input_bytes);
    let bytes = match format {
        OutputFormat::Der => info.der.clone(),
        OutputFormat::Pem => {
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &info.der)?
                .into_bytes()
        }
        OutputFormat::Text
        | OutputFormat::Json
        | OutputFormat::Jsonl
        | OutputFormat::Yaml
        | OutputFormat::Messagepack
        | OutputFormat::Cbor
        | OutputFormat::Toml => {
            let value = encoding::binary(report::inspect(&info, summary)?)?;
            match format {
                OutputFormat::Json => {
                    let mut s = serde_json::to_vec_pretty(&encoding::textual(value)?)?;
                    s.push(b'\n');
                    s
                }
                OutputFormat::Jsonl => {
                    let mut bytes = serde_json::to_vec(&encoding::textual(value)?)?;
                    bytes.push(b'\n');
                    bytes
                }
                OutputFormat::Yaml => {
                    serde_yaml_ng::to_string(&encoding::textual(value)?)?.into_bytes()
                }
                OutputFormat::Messagepack => rmp_serde::to_vec_named(&value)?,
                OutputFormat::Cbor => {
                    let mut out = Vec::new();
                    ciborium::into_writer(&value, &mut out)?;
                    out
                }
                OutputFormat::Toml => {
                    toml::to_string_pretty(&report::toml_value(encoding::textual(value)?)?)?
                        .into_bytes()
                }
                OutputFormat::Text => report::text(&encoding::textual(value)?).into_bytes(),
                OutputFormat::Der | OutputFormat::Pem => unreachable!("handled above"),
            }
        }
    };
    write_output(output, bytes)
}

fn write_output(output: Option<PathBuf>, bytes: Vec<u8>) -> Result<()> {
    match output
        .as_deref()
        .filter(|p| *p != std::path::Path::new("-"))
    {
        Some(path) => std::fs::write(path, bytes)?,
        None => std::io::stdout().lock().write_all(&bytes)?,
    }
    Ok(())
}
fn main() {
    let args = Args::parse();
    if args.summary && matches!(args.format, OutputFormat::Der | OutputFormat::Pem) {
        Args::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "--summary applies only to reports",
            )
            .exit();
    }
    if let Err(error) = run(args) {
        eprintln!("x509-info: {error}");
        std::process::exit(1);
    }
}
