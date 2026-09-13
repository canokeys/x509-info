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
    assert_eq!(info.signature_algorithm.oid, "1.2.840.10045.4.3.2");
    assert_eq!(info.signature_unused_bits, 0);
    assert_eq!(info.public_key.algorithm.oid, "1.2.840.10045.2.1");
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
    assert_eq!(info.public_key.algorithm.oid, "1.2.840.10045.2.99");
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
    assert_eq!(info.public_key.algorithm.oid, "1.2.840.113549.1.1.1");
    assert_eq!(info.public_key.key_size_bits, Some(2048));
    assert_eq!(info.public_key.curve_oid, None);
    assert!(info.public_key.encoded_key_bits > 2048);
}

const DETAILS: &[u8] = include_bytes!("fixtures/details.pem");

#[test]
fn structured_details_preserve_names_and_decode_common_extensions() {
    use x509_info::{ExtensionDetails as E, GeneralName};
    let info = parse_pem(DETAILS, ParseOptions::default()).unwrap();
    assert_eq!(info.subject.rdns.len(), 4);
    assert_eq!(info.subject.rdns[1].len(), 2);
    let attrs: Vec<_> = info.subject.rdns.iter().flatten().collect();
    assert_eq!(attrs.iter().filter(|a| a.oid == "2.5.4.11").count(), 2);
    assert!(attrs.iter().any(|a| a.value.as_deref() == Some("München")));
    let custom = attrs.iter().find(|a| a.oid == "1.2.3.4").unwrap();
    assert_eq!(custom.label, None);
    assert_eq!(custom.value.as_deref(), Some("Custom"));
    assert_eq!(custom.value_hex, "437573746f6d");
    let extension = |oid| {
        &info
            .extensions
            .iter()
            .find(|e| e.oid == oid)
            .unwrap()
            .details
    };
    assert!(matches!(
        extension("2.5.29.19"),
        E::BasicConstraints {
            ca: false,
            path_len_constraint: None
        }
    ));
    let E::KeyUsage(ku) = extension("2.5.29.15") else {
        panic!("expected KU")
    };
    assert!(ku.digital_signature);
    assert!(!ku.key_cert_sign);
    let E::ExtendedKeyUsage(eku) = extension("2.5.29.37") else {
        panic!("expected EKU")
    };
    assert_eq!(eku[0].name.as_deref(), Some("client_auth"));
    assert_eq!(eku[1].oid, "1.2.3.5");
    assert_eq!(eku[1].name, None);
    let E::SubjectAlternativeName(san) = extension("2.5.29.17") else {
        panic!("expected SAN")
    };
    assert_eq!(
        san,
        &[
            GeneralName::Dns("example.invalid".into()),
            GeneralName::Email("test@example.invalid".into()),
            GeneralName::Ip("192.0.2.1".into()),
            GeneralName::Ip("2001:db8::1".into()),
            GeneralName::Uri("https://example.invalid/cert".into()),
        ]
    );
    assert_eq!(extension("1.2.3.6"), &E::Unsupported);
    assert!(info.extensions.iter().all(|e| !e.duplicate));
    let summary = info.summary();
    drop(info);
    assert_eq!(summary.public_key.curve_name.as_deref(), Some("P-256"));
    assert_eq!(summary.subject.rdns.len(), 4);
}

#[test]
fn malformed_and_duplicate_extensions_remain_visible() {
    use x509_info::ExtensionDetails as E;
    let original = parse_pem(DETAILS, ParseOptions::default()).unwrap();
    // Mutations keep certificate framing intact; signatures are intentionally invalid.
    // Replace the unknown OID with Basic Constraints to create a duplicate whose
    // inner NULL is not a valid BasicConstraints SEQUENCE.
    let mut der = original.der.clone();
    let unknown_oid = [6, 3, 42, 3, 6];
    let offset = der.windows(5).position(|w| w == unknown_oid).unwrap();
    der[offset..offset + 5].copy_from_slice(&[6, 3, 85, 29, 19]);
    let info = parse_der(&der, ParseOptions::default()).unwrap();
    let duplicates: Vec<_> = info
        .extensions
        .iter()
        .filter(|e| e.oid == "2.5.29.19")
        .collect();
    assert_eq!(duplicates.len(), 2);
    assert!(duplicates.iter().all(|e| e.duplicate));
    assert_eq!(duplicates[1].details, E::Malformed);
    assert_eq!(duplicates[1].value_der, [5, 0]);

    let mut der = original.der;
    let dns = b"example.invalid";
    let offset = der.windows(dns.len()).position(|w| w == dns).unwrap();
    der[offset] = 0xff;
    let info = parse_der(&der, ParseOptions::default()).unwrap();
    let san = &info
        .extensions
        .iter()
        .find(|e| e.oid == "2.5.29.17")
        .unwrap()
        .details;
    let E::SubjectAlternativeName(names) = san else {
        panic!("expected SAN")
    };
    assert_eq!(names[0], x509_info::GeneralName::Malformed(2));
}

#[test]
fn eddsa_sizes_are_nominal_and_pss_parameters_are_explicit() {
    use x509_info::ParameterStatus;
    for (pem, name, bits, encoded) in [
        (
            include_bytes!("fixtures/ed25519.pem").as_slice(),
            "Ed25519",
            255,
            256,
        ),
        (
            include_bytes!("fixtures/ed448.pem").as_slice(),
            "Ed448",
            448,
            456,
        ),
    ] {
        let info = parse_pem(pem, ParseOptions::default()).unwrap();
        assert_eq!(info.public_key.algorithm.name.as_deref(), Some(name));
        assert_eq!(info.signature_algorithm.name.as_deref(), Some(name));
        assert_eq!(info.public_key.key_size_bits, Some(bits));
        assert_eq!(info.public_key.encoded_key_bits, encoded);
        assert_eq!(
            info.signature_algorithm.parameter_status,
            ParameterStatus::Absent
        );
    }
    let info = parse_pem(include_bytes!("fixtures/pss.pem"), ParseOptions::default()).unwrap();
    assert_eq!(info.public_key.key_size_bits, Some(2048));
    for alg in [&info.public_key.algorithm, &info.signature_algorithm] {
        assert_eq!(alg.name.as_deref(), Some("RSA-PSS"));
        assert_eq!(alg.parameter_status, ParameterStatus::Decoded);
        let pss = alg.pss.as_ref().unwrap();
        assert_eq!(pss.hash_oid, "2.16.840.1.101.3.4.2.1");
        assert_eq!(pss.mask_gen_oid, "1.2.840.113549.1.1.8");
        assert_eq!(
            pss.mask_gen_hash_oid.as_deref(),
            Some("2.16.840.1.101.3.4.2.1")
        );
        assert_eq!(pss.salt_length, 32);
        assert_eq!(pss.trailer_field, 1);
    }
}

#[test]
fn fingerprint_matches_independent_fixture_digest() {
    let info = parse_pem(DETAILS, ParseOptions::default()).unwrap();
    assert_eq!(
        hex::encode(info.sha256_fingerprint()),
        include_str!("fixtures/details.sha256").trim()
    );
}

#[cfg(feature = "serde")]
#[test]
fn summary_json_contract_matches_golden_without_raw_certificate_copies() {
    let info = parse_pem(DETAILS, ParseOptions::default()).unwrap();
    let value = serde_json::to_value(info.summary()).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/details.json")).unwrap();
    assert_eq!(value, expected);
    for omitted in ["der", "signature_value", "serial_number"] {
        assert!(value.get(omitted).is_none());
    }
    assert!(value["public_key"].get("spki_der").is_none());
    assert!(value["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e.get("value_der").is_none()));
}

#[test]
fn single_byte_mutation_smoke_keeps_certificate_parsing_panic_free() {
    for pem in [
        DETAILS,
        include_bytes!("fixtures/pss.pem").as_slice(),
        include_bytes!("fixtures/locations.pem").as_slice(),
    ] {
        let original = parse_pem(pem, ParseOptions::default()).unwrap().der;
        for index in 0..original.len() {
            for replacement in [0, 0x80, 0xff] {
                let mut bytes = original.clone();
                bytes[index] = replacement;
                // Invalid syntax may fail; decodable but untrusted data may succeed.
                // Either outcome is acceptable, but no card-controlled byte may panic.
                let _ = parse_der(&bytes, ParseOptions::default());
            }
        }
    }
}
