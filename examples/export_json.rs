//! Bounded file input and JSON output belong to the application.
use std::io::Read;
use x509_info::{parse_der_with_names, parse_pem_with_names, OidNames, ParseOptions};

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
    let names = OidNames::default();
    let info = if input.trim_ascii().starts_with(b"-----BEGIN ") {
        parse_pem_with_names(&input, options, &names)?
    } else {
        parse_der_with_names(&input, options, &names)?
    };
    drop(input);
    drop(names);
    let summary = info.summary();
    drop(info);
    // The owned summary can be serialized after all parsing inputs are released.
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
