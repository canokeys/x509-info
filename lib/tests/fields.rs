use crate::*;
fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 128);
    [vec![tag, data.len() as u8], data.to_vec()].concat()
}
fn seq(data: &[u8]) -> Vec<u8> {
    tlv(0x30, data)
}
fn other(oid: &str, der: &[u8]) -> GeneralName {
    GeneralName::OtherName {
        oid: oid.into(),
        name: None,
        value_der_hex: hex::encode(tlv(0xa0, der)),
    }
}
fn key() -> PublicKeyInfo {
    parse_pem(
        include_bytes!("../../tests/fixtures/details.pem"),
        ParseOptions::default(),
    )
    .unwrap()
    .public_key
}
#[test]
fn unicode_fields_preserve_raw_encoding_and_report_failures() {
    for (der, expected) in [
        (tlv(30, &[0x4e, 0x2d]), "中"),
        (tlv(28, &[0, 1, 0xf6, 0]), "😀"),
        (tlv(26, b"visible"), "visible"),
    ] {
        let name = seq(&tlv(
            0x31,
            &seq(&[vec![6, 3, 85, 4, 3], der.clone()].concat()),
        ));
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::x509::X509Name::from_der(&name).unwrap();
        let value = crate::names::inspect_name(&parsed, &OidNames::default());
        assert_eq!(value.rdns[0][0].value.as_deref(), Some(expected));
        assert!(value.rdns[0][0].diagnostic().is_none());
        let a = DirectoryAttribute {
            oid: "1.2".into(),
            name: None,
            values_der_hex: vec![hex::encode(der)],
        };
        assert_eq!(a.text_values()[0].as_ref().unwrap(), expected);
    }
    for der in [
        tlv(30, &[0xd8, 0]),
        tlv(30, &[0]),
        tlv(28, &[0, 0x11, 0, 0]),
    ] {
        assert_eq!(
            crate::decoding::text(&crate::decoding::any(&der).unwrap())
                .unwrap_err()
                .issue,
            DecodeIssue::InvalidEncoding
        );
    }
    assert_eq!(
        crate::decoding::text(&crate::decoding::any(&tlv(20, b"ambiguous")).unwrap())
            .unwrap_err()
            .issue,
        DecodeIssue::UnsupportedEncoding
    );
}
#[test]
fn other_names_and_edi_decode_owned_fields_without_identity_policy() {
    assert_eq!(
        other("1.3.6.1.4.1.311.20.2.3", &tlv(12, b"not-an-account"))
            .details()
            .unwrap(),
        Some(NameDetails::UserPrincipalName("not-an-account".into()))
    );
    let hw = seq(&[vec![6, 3, 42, 3, 4], tlv(4, &[0, 0xff])].concat());
    assert_eq!(
        other("1.3.6.1.5.5.7.8.4", &hw).details().unwrap(),
        Some(NameDetails::HardwareModule {
            type_oid: "1.2.3.4".into(),
            serial_hex: "00ff".into()
        })
    );
    assert!(other("1.2.3.4", &[0xff]).details().unwrap().is_none());
    assert!(other("1.3.6.1.4.1.311.20.2.3", &[5, 0]).details().is_err());
    let edi = GeneralName::EdiPartyName {
        constructed: true,
        content_hex: hex::encode(
            [tlv(0xa0, &tlv(30, &[0, 65])), tlv(0xa1, &tlv(12, b"party"))].concat(),
        ),
    };
    assert_eq!(
        edi.details().unwrap(),
        Some(NameDetails::EdiPartyName {
            name_assigner: Some("A".into()),
            party_name: "party".into()
        })
    );
}
#[test]
fn notices_keep_signed_large_repeated_numbers_and_all_display_text_choices() {
    for text in [
        tlv(12, b"Notice"),
        tlv(22, b"Notice"),
        tlv(26, b"Notice"),
        tlv(30, &[0, 78, 0, 111, 0, 116, 0, 105, 0, 99, 0, 101]),
    ] {
        let reference = seq(&[
            tlv(26, b"Org"),
            seq(&[
                vec![2, 1, 255, 2, 1, 255],
                tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0]),
            ]
            .concat()),
        ]
        .concat());
        let notice = seq(&[reference, text].concat());
        let qualifier = seq(&[vec![6, 8, 43, 6, 1, 5, 5, 7, 2, 2], notice.clone()].concat());
        let encoded = seq(&seq(&[vec![6, 1, 42], seq(&qualifier)].concat()));
        let p = crate::extensions::policies::decode(&encoded, &OidNames::default()).unwrap();
        let PolicyQualifierDetails::UserNotice(n) = &p[0].qualifiers[0].details else {
            panic!()
        };
        assert_eq!(n.explicit_text.as_deref(), Some("Notice"));
        let numbers = &n.notice_reference.as_ref().unwrap().notice_numbers;
        assert_eq!(numbers[0].value, Some(-1));
        assert_eq!(numbers[0], numbers[1]);
        assert_eq!(numbers[2].value, None);
        assert_eq!(numbers[2].content_hex, "010000000000000000");
        assert_eq!(p[0].qualifiers[0].value_der_hex, hex::encode(notice));
    }
}
#[test]
fn fido_and_microsoft_fields_are_not_profile_validation() {
    use crate::extensions::device::decode;
    assert_eq!(
        decode("1.3.6.1.4.1.45724.1.1.4", &tlv(4, &[1, 2])).unwrap(),
        Some(ExtensionDetails::FidoAaguid("0102".into()))
    );
    let Some(ExtensionDetails::FidoTransports(t)) =
        decode("1.3.6.1.4.1.45724.2.1.1", &[3, 2, 0, 0xa1]).unwrap()
    else {
        panic!()
    };
    assert!(t.bluetooth_classic && t.usb);
    assert_eq!(t.unknown_bits, vec![7]);
    let der = seq(&[
        vec![6, 3, 42, 3, 4],
        vec![2, 1, 255],
        tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0]),
    ]
    .concat());
    let Some(ExtensionDetails::MicrosoftCertificateTemplate(t)) =
        decode("1.3.6.1.4.1.311.21.7", &der).unwrap()
    else {
        panic!()
    };
    assert_eq!(t.template_oid, "1.2.3.4");
    assert_eq!(t.major_version.unwrap().value, Some(-1));
    assert_eq!(t.minor_version.unwrap().value, None);
    assert_eq!(
        decode("1.3.6.1.4.1.311.20.2", &tlv(30, &[0, 65])).unwrap(),
        Some(ExtensionDetails::MicrosoftTemplateName("A".into()))
    );
    for (oid, bytes) in [
        ("1.3.6.1.4.1.45724.1.1.4", tlv(4, &[1; 16])),
        ("1.3.6.1.4.1.45724.2.1.1", vec![3, 2, 0, 0xa1]),
        ("1.3.6.1.4.1.311.21.7", der),
        ("1.3.6.1.4.1.311.20.2", tlv(30, &[0, 65])),
    ] {
        for end in 0..bytes.len() {
            assert!(decode(oid, &bytes[..end]).is_err());
        }
        assert!(decode(oid, &[bytes, vec![5, 0]].concat()).is_err());
    }
}
#[test]
fn key_fields_are_extracted_without_arithmetic_or_strength_checks() {
    let mut k = key();
    let Some(PublicKeyDetails::EcUncompressed { x_hex, y_hex }) = k.details().unwrap() else {
        panic!()
    };
    assert_eq!(x_hex.len(), 64);
    assert_eq!(y_hex.len(), 64);
    k.key_bytes = vec![3, 0, 0];
    k.encoded_key_bits = 24;
    assert_eq!(
        k.details().unwrap(),
        Some(PublicKeyDetails::EcCompressed {
            x_hex: "0000".into(),
            y_odd: true
        })
    );
    k.algorithm.oid = "1.2.840.113549.1.1.1".into();
    k.key_bytes = vec![0x30, 6, 2, 1, 0, 2, 1, 0];
    k.encoded_key_bits = 64;
    assert_eq!(
        k.details().unwrap(),
        Some(PublicKeyDetails::Rsa {
            modulus_hex: "00".into(),
            exponent_hex: "00".into()
        })
    );
    let before = k.spki_sha256_fingerprint();
    k.spki_der.push(0);
    assert_ne!(before, k.spki_sha256_fingerprint());
    let rsa = parse_pem(
        include_bytes!("../../tests/fixtures/rsa2048.pem"),
        ParseOptions::default(),
    )
    .unwrap();
    let Some(PublicKeyDetails::Rsa {
        modulus_hex,
        exponent_hex,
    }) = rsa.public_key.details().unwrap()
    else {
        panic!()
    };
    assert_eq!(modulus_hex.len(), 512);
    assert_eq!(exponent_hex, "010001");
}
#[test]
fn diagnostics_do_not_mislabel_all_failures_as_invalid_der() {
    let mut ext = ExtensionInfo {
        oid: "2.5.29.54".into(),
        critical: true,
        duplicate: false,
        value_der: vec![2, 5, 1, 0, 0, 0, 0],
        details: ExtensionDetails::Malformed,
    };
    assert_eq!(
        ext.diagnostic().unwrap().issue,
        DecodeIssue::RepresentationLimit
    );
    ext.value_der = vec![2, 1, 255];
    assert_eq!(
        ext.diagnostic().unwrap().issue,
        DecodeIssue::InvalidEncoding
    );
    ext.details = ExtensionDetails::Unsupported;
    assert_eq!(ext.diagnostic().unwrap().issue, DecodeIssue::UnknownType);
}
