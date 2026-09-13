#![cfg(feature = "serde")]
use serde::Serialize;
use x509_info::{parse_pem, ParseOptions};

#[test]
fn cbor_preserves_the_json_data_model_including_unknown_and_optional_fields() {
    for pem in [
        include_bytes!("fixtures/locations.pem").as_slice(),
        include_bytes!("fixtures/details.pem").as_slice(),
        include_bytes!("fixtures/policies.pem").as_slice(),
    ] {
        let summary = parse_pem(pem, ParseOptions::default()).unwrap().summary();
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&summary, &mut encoded).unwrap();
        // Deserialize into the application's generic value, not a certificate type.
        let decoded: serde_json::Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, serde_json::to_value(&summary).unwrap());
    }
}

#[test]
fn caller_dto_can_change_names_and_omit_nulls_for_toml() {
    #[derive(Serialize)]
    struct Inventory<'a> {
        #[serde(rename = "sha256")]
        fingerprint: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        algorithm_size: Option<usize>,
    }
    let summary = parse_pem(
        include_bytes!("fixtures/details.pem"),
        ParseOptions::default(),
    )
    .unwrap()
    .summary();
    let dto = Inventory {
        fingerprint: &summary.sha256_fingerprint_hex,
        algorithm_size: None,
    };
    let encoded = toml::to_string(&dto).unwrap();
    let decoded: toml::Value = toml::from_str(&encoded).unwrap();
    assert_eq!(
        decoded["sha256"].as_str(),
        Some(summary.sha256_fingerprint_hex.as_str())
    );
    assert!(decoded.get("algorithm_size").is_none());
    assert!(decoded.get("fingerprint").is_none());
}
