use crate::{
    extensions::additional::decode, ConstraintName, ExtensionDetails as E, GeneralName, OidNames,
    SctEntry,
};

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 256);
    let mut out = vec![tag];
    if content.len() >= 128 {
        out.push(0x81);
    }
    out.push(content.len() as u8);
    out.extend_from_slice(content);
    out
}
fn seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}
fn get(oid: &str, bytes: &[u8]) -> E {
    decode(oid, bytes, &OidNames::default()).unwrap()
}

fn constraints() -> Vec<u8> {
    let dns = seq(&[tlv(0x82, b".example.invalid"), vec![0x80, 1, 1, 0x81, 1, 2]].concat());
    let ip = seq(&tlv(0x87, &[192, 0, 2, 99, 255, 0, 255, 0]));
    let mut ipv6 = [0xff; 32];
    ipv6[..16].fill(0);
    ipv6[0] = 0x20;
    ipv6[1] = 1;
    ipv6[31] = 0;
    seq(&[
        tlv(0xa0, &[dns, ip, seq(&tlv(0x87, &ipv6))].concat()),
        tlv(0xa1, &seq(&tlv(0x87, &[1, 2, 3]))),
    ]
    .concat())
}

fn mappings() -> Vec<u8> {
    let pair = seq(&[6, 3, 42, 3, 4, 6, 3, 42, 3, 5]);
    seq(&[pair.clone(), pair].concat())
}
fn attributes() -> Vec<u8> {
    seq(&seq(&[
        vec![6, 3, 42, 3, 4],
        tlv(0x31, &[4, 1, 0xff, 12, 1, b'a']),
    ]
    .concat()))
}
fn sct() -> Vec<u8> {
    let mut entry = vec![0];
    entry.extend_from_slice(&[0xab; 32]);
    entry.extend_from_slice(&1234567890123u64.to_be_bytes());
    entry.extend_from_slice(&[0, 1, 0x42, 4, 3, 0, 2, 0x30, 0]);
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend(entry);
    list.extend_from_slice(&[0, 2, 7, 0xcc]); // Unknown version stays opaque.
    tlv(
        4,
        &[(list.len() as u16).to_be_bytes().to_vec(), list].concat(),
    )
}

#[test]
fn constraints_keep_masks_distances_and_malformed_ip_values() {
    let E::NameConstraints(value) = get("2.5.29.30", &constraints()) else {
        panic!()
    };
    let permitted = value.permitted_subtrees.unwrap();
    assert_eq!(permitted.len(), 3);
    assert_eq!(
        permitted[0].base,
        ConstraintName::Name(GeneralName::Dns(".example.invalid".into()))
    );
    assert_eq!(permitted[0].minimum, 1);
    assert_eq!(permitted[0].maximum, Some(2));
    assert_eq!(permitted[1].minimum, 0);
    assert_eq!(permitted[1].maximum, None);
    assert_eq!(
        permitted[1].base,
        ConstraintName::Ip {
            address: "192.0.2.99".into(),
            mask: "255.0.255.0".into()
        }
    );
    assert_eq!(
        permitted[2].base,
        ConstraintName::Ip {
            address: "2001::".into(),
            mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00".into()
        }
    );
    assert_eq!(
        value.excluded_subtrees.unwrap()[0].base,
        ConstraintName::MalformedIp("010203".into())
    );
}

#[test]
fn policy_counters_pairs_and_directory_values_are_preserved() {
    let result = {
        let mut names = OidNames::default();
        names.insert("1.2.3.4", "Private policy").unwrap();
        decode("2.5.29.33", &mappings(), &names).unwrap()
    };
    let E::PolicyMappings(pairs) = result else {
        panic!()
    };
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], pairs[1]);
    assert_eq!(
        pairs[0].issuer_domain_policy_name.as_deref(),
        Some("Private policy")
    );
    assert_eq!(pairs[0].subject_domain_policy, "1.2.3.5");
    let E::PolicyConstraints(p) = get("2.5.29.36", &[0x30, 6, 0x80, 1, 0, 0x81, 1, 3]) else {
        panic!()
    };
    assert_eq!(p.require_explicit_policy, Some(0));
    assert_eq!(p.inhibit_policy_mapping, Some(3));
    assert_eq!(get("2.5.29.54", &[2, 1, 0]), E::InhibitAnyPolicy(0));
    let E::SubjectDirectoryAttributes(a) = get("2.5.29.9", &attributes()) else {
        panic!()
    };
    assert_eq!(a[0].oid, "1.2.3.4");
    assert_eq!(a[0].values_der_hex, ["0401ff", "0c0161"]);
}

#[test]
fn times_tls_markers_and_legacy_flags_are_inspection_data() {
    let E::PrivateKeyUsagePeriod(p) = get("2.5.29.16", &seq(&tlv(0x80, b"19700101000000Z"))) else {
        panic!()
    };
    assert_eq!(p.not_before_unix, Some(0));
    assert_eq!(p.not_after_unix, None);
    assert_eq!(
        get(
            "1.3.6.1.5.5.7.1.24",
            &[0x30, 11, 2, 1, 5, 2, 3, 0, 255, 255, 2, 1, 5]
        ),
        E::TlsFeatures(vec![5, 65535, 5])
    );
    assert_eq!(get("1.3.6.1.5.5.7.48.1.5", &[5, 0]), E::OcspNoCheck);
    assert_eq!(get("1.3.6.1.4.1.11129.2.4.3", &[5, 0]), E::CtPoison);
    assert_eq!(
        get("2.16.840.1.113730.1.13", &tlv(22, b"<opaque comment>")),
        E::NetscapeComment("<opaque comment>".into())
    );
    let E::NetscapeCertificateType(n) = get("2.16.840.1.113730.1.1", &[3, 2, 0, 0xa8]) else {
        panic!()
    };
    assert!(n.ssl_client && n.smime && n.reserved);
    assert!(!n.ssl_server && !n.object_signing && !n.ssl_ca && !n.smime_ca && !n.object_signing_ca);
}

#[test]
fn sct_keeps_unknown_versions_and_checks_all_vector_boundaries() {
    let encoded = sct();
    let E::SignedCertificateTimestamps(entries) = get("1.3.6.1.4.1.11129.2.4.2", &encoded) else {
        panic!()
    };
    let SctEntry::V1(v) = &entries[0] else {
        panic!()
    };
    assert_eq!(v.log_id_hex, "ab".repeat(32));
    assert_eq!(v.timestamp_unix_ms, 1234567890123);
    assert_eq!((v.hash_algorithm, v.signature_algorithm), (4, 3));
    assert_eq!(v.extensions_hex, "42");
    assert_eq!(v.signature_hex, "3000");
    assert_eq!(
        entries[1],
        SctEntry::Unknown {
            version: 7,
            encoded_hex: "07cc".into()
        }
    );
    // Unconsumed bytes inside the OCTET STRING, the list, and a known SCT entry.
    for layer in 0..3 {
        let mut bad = encoded.clone();
        if layer == 2 {
            bad.insert(55, 0xff);
        } else {
            bad.push(0xff);
        }
        bad[1] += 1;
        if layer >= 1 {
            bad[3] += 1;
        }
        if layer == 2 {
            bad[5] += 1;
        }
        assert!(
            decode("1.3.6.1.4.1.11129.2.4.2", &bad, &OidNames::default()).is_none(),
            "layer {layer}"
        );
    }
}

#[test]
fn all_new_decoders_reject_truncation_and_trailing_objects() {
    let examples = [
        ("2.5.29.30", constraints()),
        ("2.5.29.36", vec![0x30, 3, 0x80, 1, 0]),
        ("2.5.29.33", mappings()),
        ("2.5.29.54", vec![2, 1, 1]),
        ("2.5.29.16", seq(&tlv(0x81, b"20300101000000Z"))),
        ("2.5.29.9", attributes()),
        ("1.3.6.1.5.5.7.1.24", vec![0x30, 3, 2, 1, 5]),
        ("1.3.6.1.5.5.7.48.1.5", vec![5, 0]),
        ("1.3.6.1.4.1.11129.2.4.3", vec![5, 0]),
        ("1.3.6.1.4.1.11129.2.4.2", sct()),
        ("2.16.840.1.113730.1.13", tlv(22, b"hello")),
        ("2.16.840.1.113730.1.1", vec![3, 2, 7, 0x80]),
    ];
    for (oid, bytes) in examples {
        assert!(decode(oid, &bytes, &OidNames::default()).is_some(), "{oid}");
        for end in 0..bytes.len() {
            assert!(
                decode(oid, &bytes[..end], &OidNames::default()).is_none(),
                "{oid} prefix {end}"
            );
        }
        let trailing = [bytes, vec![5, 0]].concat();
        assert!(
            decode(oid, &trailing, &OidNames::default()).is_none(),
            "{oid} trailing"
        );
    }
    for (oid, bytes) in [
        ("2.5.29.30", seq(&[0xa0, 0])),
        ("2.5.29.30", seq(&[])),
        ("2.5.29.36", seq(&[5, 0])),
        ("2.5.29.36", seq(&[])),
        ("2.5.29.16", seq(&[5, 0])),
        ("2.5.29.16", seq(&[])),
        ("2.5.29.33", seq(&[])),
        ("2.5.29.9", seq(&[])),
        ("2.5.29.9", seq(&seq(&[6, 1, 42, 0x31, 0]))),
        ("2.5.29.54", vec![2, 1, 255]),
        ("2.5.29.54", vec![2, 5, 1, 0, 0, 0, 0]),
        ("1.3.6.1.5.5.7.1.24", seq(&[2, 3, 1, 0, 0])),
        ("1.3.6.1.5.5.7.1.24", seq(&[])),
        ("2.16.840.1.113730.1.1", vec![3, 2, 7, 0x81]),
        ("2.16.840.1.113730.1.1", vec![3, 3, 0, 0, 1]),
    ] {
        assert!(
            decode(oid, &bytes, &OidNames::default()).is_none(),
            "{oid}: {bytes:x?}"
        );
    }
}

#[cfg(feature = "serde")]
#[test]
fn added_extension_data_is_format_neutral() {
    let values = [
        get("2.5.29.30", &constraints()),
        get("2.5.29.33", &mappings()),
        get("2.5.29.9", &attributes()),
        get("1.3.6.1.4.1.11129.2.4.2", &sct()),
    ];
    let json = serde_json::to_value(&values).unwrap();
    assert_eq!(json[0]["kind"], "name_constraints");
    assert_eq!(
        json[0]["value"]["permitted_subtrees"][1]["base"]["value"]["mask"],
        "255.0.255.0"
    );
    assert_eq!(
        json[3]["value"][0]["value"]["timestamp_unix_ms"],
        1234567890123u64
    );
    let mut cbor = Vec::new();
    ciborium::into_writer(&values, &mut cbor).unwrap();
    let decoded: serde_json::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert_eq!(decoded, json);
}

#[test]
fn public_certificate_results_keep_added_extensions_raw_data_and_duplicates() {
    use x509_cert::der::{
        asn1::{ObjectIdentifier, OctetString},
        Any, Decode, Encode, Tag, TagNumber, Tagged,
    };
    let info = crate::parse_pem(
        include_bytes!("../../tests/fixtures/details.pem"),
        crate::ParseOptions::default(),
    )
    .unwrap();
    let mut certificate = Vec::<Any>::from_der(&info.der).unwrap();
    let mut tbs = Vec::<Any>::from_der(&certificate[0].to_der().unwrap()).unwrap();
    let inputs = [
        ("2.5.29.30", constraints()),
        ("2.5.29.36", vec![0x30, 3, 0x80, 1, 0]),
        ("2.5.29.33", mappings()),
        ("2.5.29.54", vec![2, 1, 1]),
        ("2.5.29.16", seq(&tlv(0x81, b"20300101000000Z"))),
        ("2.5.29.9", attributes()),
        ("1.3.6.1.5.5.7.1.24", seq(&[2, 1, 5])),
        ("1.3.6.1.5.5.7.48.1.5", vec![5, 0]),
        ("1.3.6.1.4.1.11129.2.4.3", vec![5, 0]),
        ("1.3.6.1.4.1.11129.2.4.2", sct()),
        ("2.16.840.1.113730.1.13", tlv(22, b"hello")),
        ("2.16.840.1.113730.1.1", vec![3, 2, 7, 0x80]),
        ("2.5.29.36", seq(&[5, 0])), // Duplicate with malformed nested data.
    ];
    let extensions: Vec<x509_cert::ext::Extension> = inputs
        .iter()
        .map(|(oid, value)| x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new(oid).unwrap(),
            critical: true,
            extn_value: OctetString::new(value.clone()).unwrap(),
        })
        .collect();
    let tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(3),
    };
    assert_eq!(tbs.pop().unwrap().tag(), tag);
    tbs.push(Any::new(tag, extensions.to_der().unwrap()).unwrap());
    certificate[0] = Any::from_der(&tbs.to_der().unwrap()).unwrap();
    let der = certificate.to_der().unwrap();
    // The original signature is intentionally invalid: inspection does not verify it.
    let parsed = crate::parse_der(&der, crate::ParseOptions::default()).unwrap();
    drop(der);
    let summary = parsed.summary();
    for (index, (oid, raw)) in inputs.iter().enumerate() {
        let ext = &parsed.extensions[index];
        assert_eq!(&ext.oid, oid);
        assert_eq!(&ext.value_der, raw);
        assert!(ext.critical);
        assert_eq!(ext.duplicate, *oid == "2.5.29.36");
        assert_eq!(ext.details, summary.extensions[index].details);
        if index + 1 == inputs.len() {
            assert_eq!(ext.details, E::Malformed);
        } else {
            assert!(!matches!(ext.details, E::Unsupported | E::Malformed));
        }
    }
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["extensions"][0]["details"]["kind"], "name_constraints");
        let mut cbor = Vec::new();
        ciborium::into_writer(&summary, &mut cbor).unwrap();
        let decoded: serde_json::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(decoded, json);
    }
}
