//! Inspect a certificate from a bounded application-owned file read, or an offline fixture.
use canokey::x509::{parse_der, parse_pem, ParseOptions};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ParseOptions::default();
    let bytes = if let Some(path) = std::env::args_os().nth(1) {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(options.max_input_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        bytes
    } else {
        include_bytes!("../../x509-info/tests/fixtures/inspection.pem").to_vec()
    };
    let info = if bytes.trim_ascii().starts_with(b"-----BEGIN ") {
        parse_pem(&bytes, options)?
    } else {
        parse_der(&bytes, options)?
    };
    // JSON is an application choice: FRB can instead map the owned struct to a DTO.
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}
