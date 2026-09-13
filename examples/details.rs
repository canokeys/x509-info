//! A certificate details view using only the public owned model.
use x509_info::{parse_pem, ExtensionDetails, ParseOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let summary = {
        let input = include_bytes!("../tests/fixtures/details.pem").to_vec();
        parse_pem(&input, ParseOptions::default())?.summary()
    }; // Input and full parsed certificate are already dropped.
    for (label, name) in [("Subject", &summary.subject), ("Issuer", &summary.issuer)] {
        println!("{label}:");
        for (index, rdn) in name.rdns.iter().enumerate() {
            for attr in rdn {
                println!(
                    "  RDN {index}: {} = {}",
                    attr.label.as_deref().unwrap_or(&attr.oid),
                    attr.value.as_deref().unwrap_or(&attr.value_hex)
                );
            }
        }
    }
    println!("Serial: {}", summary.serial_number_hex);
    println!("SHA-256: {}", summary.sha256_fingerprint_hex);
    println!(
        "Validity (Unix seconds): {}..={}",
        summary.validity.not_before_unix, summary.validity.not_after_unix
    );
    println!("Public key: {:?}", summary.public_key);
    println!("Signature algorithm: {:?}", summary.signature_algorithm);
    for extension in &summary.extensions {
        println!(
            "Extension {} (critical={}, duplicate={}):",
            extension.oid, extension.critical, extension.duplicate
        );
        match &extension.details {
            ExtensionDetails::SubjectAlternativeName(names) => println!("  Identities: {names:?}"),
            ExtensionDetails::KeyUsage(usage) => println!("  Key usage: {usage:?}"),
            ExtensionDetails::ExtendedKeyUsage(purposes) => println!("  Purposes: {purposes:?}"),
            ExtensionDetails::BasicConstraints {
                ca,
                path_len_constraint,
            } => println!("  CA={ca}, path length={path_len_constraint:?}"),
            other => println!("  {other:?}; raw bytes are available in the full result"),
        }
    }
    Ok(())
}
