use crate::names::inspect_name;
use crate::NameAttribute;
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
    /// Unsupported GeneralName choice, identified by its context-specific tag.
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

fn general_name(name: &backend::GeneralName<'_>) -> GeneralName {
    use backend::GeneralName as B;
    match name {
        B::DNSName(s) => GeneralName::Dns((*s).into()),
        B::RFC822Name(s) => GeneralName::Email((*s).into()),
        B::URI(s) => GeneralName::Uri((*s).into()),
        B::DirectoryName(n) => GeneralName::Directory(inspect_name(n).rdns),
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
        B::OtherName(_, _) => GeneralName::Unsupported(0),
        B::X400Address(_) => GeneralName::Unsupported(3),
        B::EDIPartyName(_) => GeneralName::Unsupported(5),
        B::Invalid(tag, _) => GeneralName::Malformed(tag.0),
    }
}

pub(crate) fn decode(oid: &str, bytes: &[u8]) -> ExtensionDetails {
    decode_supported(oid, bytes).unwrap_or(ExtensionDetails::Malformed)
}

fn decode_supported(oid: &str, bytes: &[u8]) -> Option<ExtensionDetails> {
    match oid {
        "2.5.29.17" => {
            let (rest, san) = backend::SubjectAlternativeName::from_der(bytes).ok()?;
            if !rest.is_empty() || san.general_names.is_empty() {
                return None;
            }
            Some(ExtensionDetails::SubjectAlternativeName(
                san.general_names.iter().map(general_name).collect(),
            ))
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
                        let name = match oid.as_str() {
                            "2.5.29.37.0" => Some("any_extended_key_usage"),
                            "1.3.6.1.5.5.7.3.1" => Some("server_auth"),
                            "1.3.6.1.5.5.7.3.2" => Some("client_auth"),
                            "1.3.6.1.5.5.7.3.3" => Some("code_signing"),
                            "1.3.6.1.5.5.7.3.4" => Some("email_protection"),
                            "1.3.6.1.5.5.7.3.8" => Some("time_stamping"),
                            "1.3.6.1.5.5.7.3.9" => Some("ocsp_signing"),
                            _ => None,
                        }
                        .map(str::to_owned);
                        KeyPurpose { oid, name }
                    })
                    .collect(),
            ))
        }
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
        assert_eq!(names, [GeneralName::Unsupported(3)]);
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
