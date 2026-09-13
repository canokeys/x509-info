//! Bounded file input and JSON output belong to the application.
use std::io::Read;
use x509_info::{parse_der, parse_pem, ParseOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ParseOptions::default();
    let input = match std::env::args_os().nth(1) {
        Some(path) => {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(options.max_input_bytes as u64 + 1)
                .read_to_end(&mut bytes)?;
            bytes
        }
        None => include_bytes!("../tests/fixtures/details.pem").to_vec(),
    };
    let info = if input.trim_ascii().starts_with(b"-----BEGIN ") {
        parse_pem(&input, options)?
    } else {
        parse_der(&input, options)?
    };
    println!("{}", serde_json::to_string_pretty(&info.summary())?);
    Ok(())
}
