//! Users choose serializers and DTOs; neither CBOR nor TOML is a library dependency.
use serde::Serialize;
use x509_info::{parse_pem, ParseOptions};

// TOML has no null value and is intended for tables rather than an arbitrary
// certificate tree. This application chooses a small, explicit export schema.
#[derive(Serialize)]
struct InventoryEntry<'a> {
    subject: &'a str,
    fingerprint_sha256: &'a str,
    not_before_unix: i64,
    not_after_unix: i64,
    public_key_oid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_bits: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let summary = parse_pem(
        include_bytes!("../tests/fixtures/locations.pem"),
        ParseOptions::default(),
    )?
    .summary();
    // CBOR represents the complete Serialize model, including nulls and enum tags.
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&summary, &mut cbor)?;
    println!("CBOR (hex): {}", hex::encode(cbor));
    // A caller-owned DTO also works for custom JSON layouts or other serializers.
    let entry = InventoryEntry {
        subject: &summary.subject.display,
        fingerprint_sha256: &summary.sha256_fingerprint_hex,
        not_before_unix: summary.validity.not_before_unix,
        not_after_unix: summary.validity.not_after_unix,
        public_key_oid: &summary.public_key.algorithm.oid,
        public_key_bits: summary.public_key.key_size_bits,
    };
    println!("TOML inventory:\n{}", toml::to_string_pretty(&entry)?);
    Ok(())
}
