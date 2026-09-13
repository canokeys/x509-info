use crate::names::inspect_name;
use crate::{
    AccessDescription, AuthorityKeyIdentifier, DistributionPoint, NameAttribute, OidNames,
};
use x509_cert::der::Decode;
use x509_parser::{
    asn1_rs::{BitString, FromDer, Oid},
    extensions as backend,
};

/// An owned GeneralName. Values are decoded, not validated as identities or URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum GeneralName {
    /// DNS text as encoded; no wildcard or hostname matching is performed.
    Dns(String),
    /// RFC822 mailbox text; no mailbox validation is performed.
    Email(String),
    /// URI text; no resource is fetched.
    Uri(String),
    /// IPv4 or IPv6 in standard textual notation.
    Ip(String),
    /// Directory name with ordered RDN groups.
    Directory(Vec<Vec<NameAttribute>>),
    /// Registered identifier in dotted-decimal notation.
    RegisteredId(String),
    /// OtherName type identifier and opaque value; no OID-specific decoder runs.
    OtherName {
        /// Dotted-decimal type-id OID.
        oid: String,
        /// Presentation label from the caller's registry, when available.
        name: Option<String>,
        /// Lowercase hex of bytes following type-id, including the expected `[0]`
        /// explicit value wrapper. The backend does not validate that wrapper
        /// or the inner value; these bytes may be empty or malformed.
        value_der_hex: String,
    },
    /// Opaque X.400 address. The backend does not decode the ORAddress fields.
    X400Address {
        /// Constructed bit of the context-specific `[3]` header as encoded.
        constructed: bool,
        /// Lowercase hex of content octets, excluding the outer tag and length.
        content_hex: String,
    },
    /// Opaque EDI party name. The backend does not decode its inner fields.
    EdiPartyName {
        /// Constructed bit of the context-specific `[5]` header as encoded.
        constructed: bool,
        /// Lowercase hex of content octets, excluding the outer tag and length.
        content_hex: String,
    },
    /// Reserved unsupported choice, identified by its context-specific tag.
    /// Retained for compatibility; current backend choices have dedicated variants.
    /// Its bytes remain in the containing extension's value_der.
    Unsupported(u32),
    /// Malformed GeneralName choice, including invalid IP lengths or text encodings.
    /// Its bytes remain in the containing extension's value_der.
    Malformed(u32),
}

/// Decoded Key Usage bits. These describe assertions, not enforced permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct KeyUsage {
    /// Digital signatures other than certificate/CRL signing.
    pub digital_signature: bool,
    /// The nonRepudiation/contentCommitment bit.
    pub content_commitment: bool,
    /// Key transport.
    pub key_encipherment: bool,
    /// Direct data encryption.
    pub data_encipherment: bool,
    /// Key agreement.
    pub key_agreement: bool,
    /// Certificate signing.
    pub key_cert_sign: bool,
    /// CRL signing.
    pub crl_sign: bool,
    /// Encipher-only key agreement.
    pub encipher_only: bool,
    /// Decipher-only key agreement.
    pub decipher_only: bool,
}

/// An Extended Key Usage purpose, preserving OIDs, order and repetitions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct KeyPurpose {
    /// Dotted-decimal key-purpose OID.
    pub oid: String,
    /// Stable common label, or None for an unknown purpose.
    pub name: Option<String>,
}

/// Application-facing interpretation of a certificate extension.
/// Malformed/unsupported values and duplicate extensions never disappear silently.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum ExtensionDetails {
    /// Subject Alternative Name entries in encoded order.
    SubjectAlternativeName(Vec<GeneralName>),
    /// Key Usage flags.
    KeyUsage(KeyUsage),
    /// Extended Key Usage purposes.
    ExtendedKeyUsage(Vec<KeyPurpose>),
    /// Basic Constraints; no trust or path policy is enforced.
    BasicConstraints {
        /// Encoded CA assertion (default false).
        ca: bool,
        /// Encoded path-length constraint, when present.
        path_len_constraint: Option<u32>,
    },
    /// Subject Key Identifier octets in lowercase hex.
    SubjectKeyIdentifier(String),
    /// Authority Key Identifier fields; no issuer matching is performed.
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// Authority Information Access entries, including OCSP/CA issuer locations.
    AuthorityInfoAccess(Vec<AccessDescription>),
    /// Subject Information Access entries, including CA repository locations.
    SubjectInfoAccess(Vec<AccessDescription>),
    /// Issuer Alternative Names, in encoded order.
    IssuerAlternativeName(Vec<GeneralName>),
    /// CRL Distribution Points; no CRL retrieval or revocation checks occur.
    CrlDistributionPoints(Vec<DistributionPoint>),
    /// Freshest CRL locations for delta CRLs; no CRL processing occurs.
    FreshestCrl(Vec<DistributionPoint>),
    /// Certificate policy OIDs and qualifiers; no policy evaluation is performed.
    CertificatePolicies(Vec<crate::CertificatePolicy>),
    /// This library does not interpret this OID. Raw bytes remain available.
    Unsupported,
    /// A supported extension could not be decoded within this library's limits.
    /// This is a finding, not a certificate-level parse failure.
    Malformed,
}

/// An extension and its decoded information, retained in certificate order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct ExtensionInfo {
    /// Dotted-decimal extension OID, including unknown OIDs.
    pub oid: String,
    /// Encoded critical flag; this library does not enforce critical extensions.
    pub critical: bool,
    /// True on every occurrence of an OID that appears more than once.
    pub duplicate: bool,
    /// Inner extnValue octets, without the outer OCTET STRING wrapper.
    pub value_der: Vec<u8>,
    /// Decoded information or an explicit unsupported/malformed state.
    pub details: ExtensionDetails,
}

pub(crate) fn general_name(name: &backend::GeneralName<'_>, names: &OidNames) -> GeneralName {
    use backend::GeneralName as B;
    match name {
        B::DNSName(s) => GeneralName::Dns((*s).into()),
        B::RFC822Name(s) => GeneralName::Email((*s).into()),
        B::URI(s) => GeneralName::Uri((*s).into()),
        B::DirectoryName(n) => GeneralName::Directory(inspect_name(n, names).rdns),
        B::RegisteredID(oid) => GeneralName::RegisteredId(oid.to_id_string()),
        B::IPAddress(bytes) => match bytes.len() {
            4 => GeneralName::Ip(
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).expect("length checked"))
                    .to_string(),
            ),
            16 => GeneralName::Ip(
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).expect("length checked"))
                    .to_string(),
            ),
            _ => GeneralName::Malformed(7),
        },
        B::OtherName(oid, value) => {
            let oid = oid.to_id_string();
            GeneralName::OtherName {
                name: names.get(&oid).map(str::to_owned),
                oid,
                value_der_hex: hex::encode(value),
            }
        }
        B::X400Address(any) => GeneralName::X400Address {
            constructed: any.header.is_constructed(),
            content_hex: hex::encode(any.data),
        },
        B::EDIPartyName(any) => GeneralName::EdiPartyName {
            constructed: any.header.is_constructed(),
            content_hex: hex::encode(any.data),
        },
        B::Invalid(tag, _) => GeneralName::Malformed(tag.0),
    }
}

#[cfg(test)]
fn decode(oid: &str, bytes: &[u8]) -> ExtensionDetails {
    decode_with_names(oid, bytes, &OidNames::default())
}

pub(crate) fn decode_with_names(oid: &str, bytes: &[u8], names: &OidNames) -> ExtensionDetails {
    decode_supported(oid, bytes, names).unwrap_or(ExtensionDetails::Malformed)
}

fn decode_supported(oid: &str, bytes: &[u8], names: &OidNames) -> Option<ExtensionDetails> {
    match oid {
        "2.5.29.17" | "2.5.29.18" => {
            let (rest, san) = backend::SubjectAlternativeName::from_der(bytes).ok()?;
            if !rest.is_empty() || san.general_names.is_empty() {
                return None;
            }
            let entries = san
                .general_names
                .iter()
                .map(|n| general_name(n, names))
                .collect();
            Some(if oid == "2.5.29.17" {
                ExtensionDetails::SubjectAlternativeName(entries)
            } else {
                ExtensionDetails::IssuerAlternativeName(entries)
            })
        }
        "2.5.29.19" => {
            let (rest, bc) = backend::BasicConstraints::from_der(bytes).ok()?;
            if !rest.is_empty() {
                return None;
            }
            Some(ExtensionDetails::BasicConstraints {
                ca: bc.ca,
                path_len_constraint: bc.path_len_constraint,
            })
        }
        "2.5.29.15" => {
            // Bound the backend's u16 flag representation before conversion; reject
            // bits beyond the nine named usages rather than silently truncating them.
            let (rest, bits) = BitString::from_der(bytes).ok()?;
            if !rest.is_empty()
                || bits.data.is_empty()
                || bits.data.len() > 2
                || bits.unused_bits > 7
                || bits.data.last()? & ((1u8 << bits.unused_bits) - 1) != 0
                || (bits.data.len() == 2 && (bits.data[1] & 0x7f != 0 || bits.unused_bits != 7))
            {
                return None;
            }
            let (_, k) = backend::KeyUsage::from_der(bytes).ok()?;
            Some(ExtensionDetails::KeyUsage(KeyUsage {
                digital_signature: k.digital_signature(),
                content_commitment: k.non_repudiation(),
                key_encipherment: k.key_encipherment(),
                data_encipherment: k.data_encipherment(),
                key_agreement: k.key_agreement(),
                key_cert_sign: k.key_cert_sign(),
                crl_sign: k.crl_sign(),
                encipher_only: k.encipher_only(),
                decipher_only: k.decipher_only(),
            }))
        }
        "2.5.29.37" => {
            // Decode the sequence directly using the backend ASN.1 types so order,
            // duplicate purposes and unknown OIDs survive its boolean convenience model.
            let (rest, oids) = Vec::<Oid<'_>>::from_der(bytes).ok()?;
            if !rest.is_empty() || oids.is_empty() {
                return None;
            }
            Some(ExtensionDetails::ExtendedKeyUsage(
                oids.iter()
                    .map(|oid| {
                        let oid = oid.to_id_string();
                        let name = names.get(&oid).map(str::to_owned);
                        KeyPurpose { oid, name }
                    })
                    .collect(),
            ))
        }
        "2.5.29.14" => {
            let (rest, key) = backend::KeyIdentifier::from_der(bytes).ok()?;
            if !rest.is_empty() {
                return None;
            }
            Some(ExtensionDetails::SubjectKeyIdentifier(hex::encode(key.0)))
        }
        "2.5.29.35" => {
            // The inspection backend accepts unconsumed optional-field content.
            // Check the complete schema first, then retain its raw INTEGER octets.
            x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(bytes).ok()?;
            let (rest, aki) = backend::AuthorityKeyIdentifier::from_der(bytes).ok()?;
            if !rest.is_empty() {
                return None;
            }
            Some(ExtensionDetails::AuthorityKeyIdentifier(
                AuthorityKeyIdentifier {
                    key_identifier_hex: aki.key_identifier.as_ref().map(|k| hex::encode(k.0)),
                    authority_cert_issuer: aki
                        .authority_cert_issuer
                        .as_ref()
                        .map(|list| list.iter().map(|n| general_name(n, names)).collect()),
                    authority_cert_serial_hex: aki.authority_cert_serial.map(hex::encode),
                },
            ))
        }
        "1.3.6.1.5.5.7.1.1" => {
            x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(bytes).ok()?;
            let (rest, aia) = backend::AuthorityInfoAccess::from_der(bytes).ok()?;
            if !rest.is_empty() || aia.accessdescs.is_empty() {
                return None;
            }
            Some(ExtensionDetails::AuthorityInfoAccess(
                crate::locations::access(&aia.accessdescs, names),
            ))
        }
        "1.3.6.1.5.5.7.1.11" => {
            x509_cert::ext::pkix::SubjectInfoAccessSyntax::from_der(bytes).ok()?;
            let (rest, sia) = backend::SubjectInfoAccess::from_der(bytes).ok()?;
            if !rest.is_empty() || sia.accessdescs.is_empty() {
                return None;
            }
            Some(ExtensionDetails::SubjectInfoAccess(
                crate::locations::access(&sia.accessdescs, names),
            ))
        }
        "2.5.29.31" | "2.5.29.46" => {
            let points = crate::locations::distribution(bytes, names)?;
            Some(if oid == "2.5.29.31" {
                ExtensionDetails::CrlDistributionPoints(points)
            } else {
                ExtensionDetails::FreshestCrl(points)
            })
        }
        "2.5.29.32" => Some(ExtensionDetails::CertificatePolicies(
            crate::policies::decode(bytes, names)?,
        )),
        _ => Some(ExtensionDetails::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions_reject_trailing_truncated_and_wrong_inner_types() {
        let examples: &[(&str, &[u8])] = &[
            ("2.5.29.19", &[0x30, 0]),
            ("2.5.29.15", &[3, 2, 7, 0x80]),
            ("2.5.29.37", &[0x30, 5, 6, 3, 42, 3, 5]),
            ("2.5.29.17", &[0x30, 3, 0x82, 1, b'a']),
            ("2.5.29.18", &[0x30, 3, 0x82, 1, b'a']),
            ("2.5.29.14", &[4, 1, 42]),
            ("2.5.29.32", &[0x30, 5, 0x30, 3, 6, 1, 42]),
            ("2.5.29.35", &[0x30, 3, 0x80, 1, 42]),
            (
                "1.3.6.1.5.5.7.1.1",
                &[
                    0x30, 15, 0x30, 13, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 0x86, 1, b'a',
                ],
            ),
            (
                "1.3.6.1.5.5.7.1.11",
                &[
                    0x30, 15, 0x30, 13, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 0x86, 1, b'a',
                ],
            ),
            (
                "2.5.29.31",
                &[0x30, 9, 0x30, 7, 0xa0, 5, 0xa0, 3, 0x86, 1, b'a'],
            ),
            (
                "2.5.29.46",
                &[0x30, 9, 0x30, 7, 0xa0, 5, 0xa0, 3, 0x86, 1, b'a'],
            ),
        ];
        for (oid, bytes) in examples {
            assert_ne!(decode(oid, bytes), ExtensionDetails::Malformed);
            for n in 0..bytes.len() {
                assert_eq!(
                    decode(oid, &bytes[..n]),
                    ExtensionDetails::Malformed,
                    "{oid} prefix {n}"
                );
            }
            assert_eq!(
                decode(oid, &[*bytes, &[0]].concat()),
                ExtensionDetails::Malformed
            );
            assert_eq!(decode(oid, &[5, 0]), ExtensionDetails::Malformed);
        }
        assert_eq!(decode("1.2.3.4", &[0xff]), ExtensionDetails::Unsupported);
    }

    #[test]
    fn optional_fields_and_nested_sequences_do_not_hide_extra_objects() {
        let cases: &[(&str, &[u8])] = &[
            ("2.5.29.35", &[0x30, 2, 5, 0]),
            ("2.5.29.31", &[0x30, 4, 0x30, 2, 5, 0]),
            (
                "1.3.6.1.5.5.7.1.1",
                &[
                    0x30, 17, 0x30, 15, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 0x86, 1, b'a', 5, 0,
                ],
            ),
            (
                "1.3.6.1.5.5.7.1.11",
                &[
                    0x30, 17, 0x30, 15, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 0x86, 1, b'a', 5, 0,
                ],
            ),
        ];
        for (oid, bytes) in cases {
            assert_eq!(decode(oid, bytes), ExtensionDetails::Malformed, "{oid}");
        }
    }

    #[test]
    fn key_usage_and_general_names_do_not_silently_drop_invalid_data() {
        for invalid in [
            &[3, 1, 0][..],
            &[3, 2, 8, 0x80],
            &[3, 2, 7, 0x81],
            &[3, 3, 6, 0, 0x40],
            &[3, 4, 0, 0, 0, 1],
        ] {
            assert_eq!(decode("2.5.29.15", invalid), ExtensionDetails::Malformed);
        }
        let ExtensionDetails::KeyUsage(ku) = decode("2.5.29.15", &[3, 3, 7, 0x08, 0x80]) else {
            panic!("expected KU")
        };
        assert!(ku.key_agreement && ku.decipher_only);
        let ExtensionDetails::SubjectAlternativeName(names) =
            decode("2.5.29.17", &[0x30, 5, 0x87, 3, 1, 2, 3])
        else {
            panic!("expected SAN")
        };
        assert_eq!(names, [GeneralName::Malformed(7)]);
        let ExtensionDetails::SubjectAlternativeName(names) =
            decode("2.5.29.17", &[0x30, 2, 0xa3, 0])
        else {
            panic!("expected SAN")
        };
        assert_eq!(
            names,
            [GeneralName::X400Address {
                constructed: true,
                content_hex: String::new()
            }]
        );
    }

    #[test]
    fn opaque_names_preserve_backend_data_and_caller_labels() {
        let entries = {
            // SAN: OtherName 1.2.3.4 with explicit UTF8 "a", opaque X.400,
            // opaque EDI, and an OtherName whose value wrapper is absent.
            let bytes = vec![
                0x30, 25, 0xa0, 10, 6, 3, 42, 3, 4, 0xa0, 3, 12, 1, b'a', 0xa3, 2, 0x30, 0, 0xa5,
                0, 0xa0, 5, 6, 3, 42, 3, 4,
            ];
            let mut names = OidNames::default();
            names.insert("1.2.3.4", "Private identity").unwrap();
            let ExtensionDetails::SubjectAlternativeName(entries) =
                decode_with_names("2.5.29.17", &bytes, &names)
            else {
                panic!("expected SAN")
            };
            entries
        }; // The input and caller registry no longer exist.
        assert_eq!(
            entries,
            vec![
                GeneralName::OtherName {
                    oid: "1.2.3.4".into(),
                    name: Some("Private identity".into()),
                    value_der_hex: "a0030c0161".into(),
                },
                GeneralName::X400Address {
                    constructed: true,
                    content_hex: "3000".into()
                },
                GeneralName::EdiPartyName {
                    constructed: true,
                    content_hex: String::new()
                },
                GeneralName::OtherName {
                    oid: "1.2.3.4".into(),
                    name: Some("Private identity".into()),
                    value_der_hex: String::new(),
                },
            ]
        );
        #[cfg(feature = "serde")]
        {
            let json = serde_json::to_value(&entries).unwrap();
            assert_eq!(
                json,
                serde_json::json!([
                    {"kind":"other_name","value":{"oid":"1.2.3.4","name":"Private identity","value_der_hex":"a0030c0161"}},
                    {"kind":"x400_address","value":{"constructed":true,"content_hex":"3000"}},
                    {"kind":"edi_party_name","value":{"constructed":true,"content_hex":""}},
                    {"kind":"other_name","value":{"oid":"1.2.3.4","name":"Private identity","value_der_hex":""}}
                ])
            );
            let mut cbor = Vec::new();
            ciborium::into_writer(&entries, &mut cbor).unwrap();
            let decoded: serde_json::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
            assert_eq!(decoded, json);
        }
    }

    #[test]
    fn eku_retains_repeated_unknown_purposes_in_order() {
        let ExtensionDetails::ExtendedKeyUsage(purposes) =
            decode("2.5.29.37", &[0x30, 10, 6, 3, 42, 3, 5, 6, 3, 42, 3, 5])
        else {
            panic!("expected EKU")
        };
        assert_eq!(purposes.len(), 2);
        assert_eq!(purposes[0], purposes[1]);
        assert_eq!(purposes[0].name, None);
    }
}
