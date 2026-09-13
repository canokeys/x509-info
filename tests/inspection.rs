use x509_info::{parse_der, parse_pem, Error, ParseOptions};

const PEM: &[u8] = include_bytes!("fixtures/inspection.pem");

#[test]
fn owns_fields_and_preserves_certificate_encodings() {
    let source = PEM.to_vec();
    let info = parse_pem(&source, ParseOptions::default()).unwrap();
    drop(source);
    assert_eq!(info.version, 3);
    assert_eq!(info.serial_number, [42]);
    assert!(info.subject.display.contains("libcanokey test certificate"));
    assert_eq!(info.subject, info.issuer);
    assert_eq!(info.signature_algorithm_oid, "1.2.840.10045.4.3.2");
    assert_eq!(info.signature_unused_bits, 0);
    assert_eq!(info.public_key.algorithm_oid, "1.2.840.10045.2.1");
    assert_eq!(
        info.public_key.curve_oid.as_deref(),
        Some("1.2.840.10045.3.1.7")
    );
    assert_eq!(info.public_key.key_size_bits, Some(256));
    assert_eq!(info.public_key.encoded_key_bits, 520);
    assert_eq!(info.public_key.key_bytes.len(), 65);
    assert!(info.public_key.spki_der.len() > info.public_key.key_bytes.len());
    assert!(info
        .extensions
        .iter()
        .any(|e| e.oid == "2.5.29.19" && e.critical));
    assert!(info
        .extensions
        .iter()
        .any(|e| e.oid == "2.5.29.17" && !e.critical));
    assert_eq!(parse_der(&info.der, ParseOptions::default()).unwrap(), info);
    let period = info.validity;
    assert!(period.contains(period.not_before_unix));
    assert!(period.contains(period.not_after_unix));
    assert!(!period.contains(period.not_before_unix - 1));
    assert!(!period.contains(period.not_after_unix + 1));
}

#[test]
fn rejects_truncation_and_der_trailing_data() {
    let der = parse_pem(PEM, ParseOptions::default()).unwrap().der;
    for n in 0..der.len() {
        assert!(
            parse_der(&der[..n], ParseOptions::default()).is_err(),
            "prefix {n}"
        );
    }
    for suffix in [&[0xfe, 0][..], der.as_slice()] {
        let mut bytes = der.clone();
        bytes.extend_from_slice(suffix);
        assert_eq!(
            parse_der(&bytes, ParseOptions::default()).unwrap_err(),
            Error::TrailingData
        );
    }
}

#[test]
fn requires_one_certificate_pem_block() {
    let mut padded = b" \t\r\n".to_vec();
    padded.extend_from_slice(PEM);
    padded.extend_from_slice(b" \n");
    assert!(parse_pem(&padded, ParseOptions::default()).is_ok());
    let mut bundle = PEM.to_vec();
    bundle.extend_from_slice(PEM);
    assert_eq!(
        parse_pem(&bundle, ParseOptions::default()).unwrap_err(),
        Error::InvalidPem
    );
    let wrong_label = String::from_utf8(PEM.to_vec())
        .unwrap()
        .replace("CERTIFICATE", "PRIVATE KEY");
    assert_eq!(
        parse_pem(wrong_label.as_bytes(), ParseOptions::default()).unwrap_err(),
        Error::UnexpectedPemLabel
    );
    for bytes in [
        b"garbage".to_vec(),
        [b"prefix".as_slice(), PEM].concat(),
        b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----".to_vec(),
    ] {
        assert_eq!(
            parse_pem(&bytes, ParseOptions::default()).unwrap_err(),
            Error::InvalidPem
        );
    }
    let suffix = [PEM, b"garbage"].concat();
    assert_eq!(
        parse_pem(&suffix, ParseOptions::default()).unwrap_err(),
        Error::InvalidPem
    );
}

#[test]
fn enforces_encoded_input_budgets() {
    let der = parse_pem(PEM, ParseOptions::default()).unwrap().der;
    for (bytes, pem) in [(PEM, true), (der.as_slice(), false)] {
        let parse = if pem { parse_pem } else { parse_der };
        assert_eq!(
            parse(bytes, ParseOptions { max_input_bytes: 0 }).unwrap_err(),
            Error::InvalidOptions
        );
        assert_eq!(
            parse(
                bytes,
                ParseOptions {
                    max_input_bytes: bytes.len() - 1
                }
            )
            .unwrap_err(),
            Error::LimitExceeded
        );
        assert!(parse(
            bytes,
            ParseOptions {
                max_input_bytes: bytes.len()
            }
        )
        .is_ok());
    }
}

#[test]
fn unknown_key_algorithm_does_not_invent_algorithm_size() {
    let mut der = parse_pem(PEM, ParseOptions::default()).unwrap().der;
    let oid = [6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
    let offset = der.windows(oid.len()).position(|w| w == oid).unwrap();
    der[offset + oid.len() - 1] = 99; // Unknown OID, unchanged DER lengths.
    let info = parse_der(&der, ParseOptions::default()).unwrap();
    assert_eq!(info.public_key.algorithm_oid, "1.2.840.10045.2.99");
    assert_eq!(info.public_key.key_size_bits, None);
    assert_eq!(info.public_key.encoded_key_bits, 520);
    // Changing TBS invalidates the signature; inspection deliberately does not verify it.
}

#[test]
fn rejects_mismatched_inner_and_outer_signature_algorithms() {
    let mut der = parse_pem(PEM, ParseOptions::default()).unwrap().der;
    let oid = [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2];
    let offset = der.windows(oid.len()).rposition(|w| w == oid).unwrap();
    der[offset + oid.len() - 1] = 3;
    assert_eq!(
        parse_der(&der, ParseOptions::default()).unwrap_err(),
        Error::InconsistentSignatureAlgorithm
    );
}

#[cfg(feature = "serde")]
#[test]
fn serializes_owned_fields_without_a_json_specific_core_api() {
    let info = parse_pem(PEM, ParseOptions::default()).unwrap();
    let value = serde_json::to_value(&info).unwrap();
    assert_eq!(value["public_key"]["key_size_bits"], 256);
    assert_eq!(value["serial_number"], serde_json::json!([42]));
    assert!(value["validity"]["not_before_unix"].is_i64());
    let mut unknown = info;
    unknown.public_key.key_size_bits = None;
    assert!(serde_json::to_value(unknown).unwrap()["public_key"]["key_size_bits"].is_null());
}

#[test]
fn named_curve_size_is_not_the_rounded_point_encoding_size() {
    let info = parse_pem(include_bytes!("fixtures/p521.pem"), ParseOptions::default()).unwrap();
    assert_eq!(info.public_key.key_size_bits, Some(521));
    assert_eq!(info.public_key.encoded_key_bits, 133 * 8);
    let mut unknown_curve = info.der;
    let oid = [6, 5, 0x2b, 0x81, 4, 0, 0x23];
    let offset = unknown_curve
        .windows(oid.len())
        .position(|w| w == oid)
        .unwrap();
    unknown_curve[offset + oid.len() - 1] = 99;
    assert_eq!(
        parse_der(&unknown_curve, ParseOptions::default())
            .unwrap()
            .public_key
            .key_size_bits,
        None
    );
}

#[test]
fn validates_matching_pem_boundaries() {
    let text = String::from_utf8(PEM.to_vec()).unwrap();
    let wrong_end = text.replace("END CERTIFICATE", "END PRIVATE KEY");
    assert_eq!(
        parse_pem(wrong_end.as_bytes(), ParseOptions::default()).unwrap_err(),
        Error::InvalidPem
    );
}

#[test]
fn rsa_size_excludes_der_integer_sign_padding() {
    let info = parse_pem(
        include_bytes!("fixtures/rsa2048.pem"),
        ParseOptions::default(),
    )
    .unwrap();
    assert_eq!(info.public_key.algorithm_oid, "1.2.840.113549.1.1.1");
    assert_eq!(info.public_key.key_size_bits, Some(2048));
    assert_eq!(info.public_key.curve_oid, None);
    assert!(info.public_key.encoded_key_bits > 2048);
}
