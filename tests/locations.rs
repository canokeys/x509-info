use x509_info::{
    parse_pem, parse_pem_with_names, DistributionPointName, ExtensionDetails as E, GeneralName,
    OidNames, ParseOptions,
};
const PEM: &[u8] = include_bytes!("fixtures/locations.pem");

#[test]
fn identifiers_access_methods_and_crl_names_preserve_all_components() {
    let info = parse_pem(PEM, ParseOptions::default()).unwrap();
    let ext = |oid| {
        &info
            .extensions
            .iter()
            .find(|e| e.oid == oid)
            .unwrap()
            .details
    };
    assert_eq!(ext("2.5.29.14"), &E::SubjectKeyIdentifier("010203".into()));
    let E::AuthorityKeyIdentifier(aki) = ext("2.5.29.35") else {
        panic!("AKI")
    };
    assert_eq!(aki.key_identifier_hex.as_deref(), Some("aabb"));
    assert_eq!(aki.authority_cert_serial_hex.as_deref(), Some("0080"));
    let GeneralName::Directory(issuer) = &aki.authority_cert_issuer.as_ref().unwrap()[0] else {
        panic!("issuer")
    };
    assert_eq!(issuer[0][0].value.as_deref(), Some("Issuer fixture"));
    let E::AuthorityInfoAccess(aia) = ext("1.3.6.1.5.5.7.1.1") else {
        panic!("AIA")
    };
    assert_eq!(aia.len(), 3);
    assert_eq!(aia[0].method_name.as_deref(), Some("ocsp"));
    assert_eq!(aia[1].method_name.as_deref(), Some("ca_issuers"));
    assert_eq!(aia[2].method_oid, "1.2.3.7");
    assert_eq!(aia[2].method_name, None);
    assert_eq!(
        aia[0].location,
        GeneralName::Uri("https://ocsp.example.invalid".into())
    );
    let E::SubjectInfoAccess(sia) = ext("1.3.6.1.5.5.7.1.11") else {
        panic!("SIA")
    };
    assert_eq!(sia[0].method_name.as_deref(), Some("ca_repository"));
    assert_eq!(
        ext("2.5.29.18"),
        &E::IssuerAlternativeName(vec![GeneralName::Email("issuer@example.invalid".into())])
    );
    let E::CrlDistributionPoints(points) = ext("2.5.29.31") else {
        panic!("CRL")
    };
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].reason_flags, Some(6));
    assert!(points[0].crl_issuer.is_some());
    let Some(DistributionPointName::RelativeName(rdn)) = &points[1].name else {
        panic!("relative name")
    };
    assert_eq!(rdn[0].value.as_deref(), Some("Relative CRL"));
    let E::FreshestCrl(delta) = ext("2.5.29.46") else {
        panic!("delta CRL")
    };
    assert_eq!(delta[0].reason_flags, None);
    assert_eq!(
        delta[0].name,
        Some(DistributionPointName::FullName(vec![GeneralName::Uri(
            "https://crl.example.invalid/delta.crl".into()
        )]))
    );
    let attrs: Vec<_> = info.subject.rdns.iter().flatten().collect();
    assert_eq!(
        attrs
            .iter()
            .find(|a| a.oid == "2.5.4.42")
            .unwrap()
            .label
            .as_deref(),
        Some("givenName")
    );
    assert_eq!(
        attrs
            .iter()
            .find(|a| a.oid == "2.5.4.4")
            .unwrap()
            .label
            .as_deref(),
        Some("surname")
    );
}

#[test]
fn caller_owned_names_change_labels_without_state_leaks_or_decoder_changes() {
    let result = {
        let mut names = OidNames::default();
        names.insert("1.2.3.7", "Internal endpoint").unwrap();
        names.insert("1.2.840.10045.2.1", "Our EC label").unwrap();
        names.insert("2.5.4.3", "Common name").unwrap();
        parse_pem_with_names(PEM, ParseOptions::default(), &names).unwrap()
    };
    assert_eq!(
        result.public_key.algorithm.name.as_deref(),
        Some("Our EC label")
    );
    assert_eq!(result.public_key.key_size_bits, Some(256));
    assert_eq!(
        result.subject.rdns[0][0].label.as_deref(),
        Some("Common name")
    );
    let E::AuthorityInfoAccess(aia) = &result
        .extensions
        .iter()
        .find(|e| e.oid == "1.3.6.1.5.5.7.1.1")
        .unwrap()
        .details
    else {
        panic!("AIA")
    };
    assert_eq!(aia[2].method_name.as_deref(), Some("Internal endpoint"));
    assert_eq!(
        parse_pem(PEM, ParseOptions::default())
            .unwrap()
            .public_key
            .algorithm
            .name
            .as_deref(),
        Some("EC")
    );
}

#[test]
fn oid_lookup_covers_new_names_without_claiming_key_support() {
    let mut names = OidNames::default();
    assert_eq!(names.get("2.16.840.1.101.3.4.3.10"), Some("ECDSA-SHA3-256"));
    assert_eq!(
        names.get("1.3.6.1.4.1.311.20.2.2"),
        Some("smart_card_logon")
    );
    assert_eq!(names.get("1.3.36.3.3.2.8.1.1.7"), Some("brainpoolP256r1"));
    assert_eq!(names.get("2.5.29.32"), Some("certificatePolicies"));
    for bad in ["", "abc", "3.1", "1.40", "1.2.", "1.02.3", "1"] {
        assert!(names.insert(bad, "bad").is_err(), "accepted {bad}");
    }
}

#[test]
fn policies_preserve_unknown_ids_cps_uris_and_unparsed_notices() {
    use x509_info::PolicyQualifierDetails as Q;
    let info = parse_pem(
        include_bytes!("fixtures/policies.pem"),
        ParseOptions::default(),
    )
    .unwrap();
    let E::CertificatePolicies(policies) = &info
        .extensions
        .iter()
        .find(|e| e.oid == "2.5.29.32")
        .unwrap()
        .details
    else {
        panic!("policies")
    };
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].oid, "2.5.29.32.0");
    assert!(policies[0].qualifiers.is_empty());
    assert_eq!(policies[1].oid, "1.2.3.9");
    assert_eq!(policies[1].name, None);
    assert_eq!(
        policies[1].qualifiers[0].details,
        Q::CpsUri("https://policy.example.invalid/cps".into())
    );
    assert_eq!(policies[1].qualifiers[1].details, Q::Unparsed);
    assert!(policies[1].qualifiers[1]
        .value_der_hex
        .contains("4578616d706c65206e6f74696365"));
}
