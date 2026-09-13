use crate::{ExtensionDetails as E, OidNames};
use x509_cert::{
    der::{
        asn1::{Ia5String, Null},
        Decode, Encode,
    },
    ext::pkix,
};

/// Policy counters asserted by the certificate, without path-policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PolicyConstraints {
    /// Number of additional certificates before an explicit policy is required.
    pub require_explicit_policy: Option<u32>,
    /// Number of additional certificates before policy mapping is inhibited.
    pub inhibit_policy_mapping: Option<u32>,
}

/// One issuer-to-subject policy mapping; order and duplicate pairs are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PolicyMapping {
    /// Issuer domain policy OID in dotted-decimal notation.
    pub issuer_domain_policy: String,
    /// Caller-configurable issuer policy label, if known.
    pub issuer_domain_policy_name: Option<String>,
    /// Subject domain policy OID in dotted-decimal notation.
    pub subject_domain_policy: String,
    /// Caller-configurable subject policy label, if known.
    pub subject_domain_policy_name: Option<String>,
}

/// Optional private-key usage bounds. This does not change certificate validity.
/// The backend accepts years 1970–9999; other encodings yield a malformed finding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PrivateKeyUsagePeriod {
    /// Inclusive start in Unix seconds, if encoded; no clock is read.
    pub not_before_unix: Option<i64>,
    /// Inclusive end in Unix seconds, if encoded; interval order is not enforced.
    pub not_after_unix: Option<i64>,
}

/// A subject directory attribute with its multi-valued ASN.1 SET preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DirectoryAttribute {
    /// Dotted-decimal attribute OID.
    pub oid: String,
    /// Caller-configurable presentation label, if known.
    pub name: Option<String>,
    /// Complete DER values in lowercase hex and encoded SET order.
    /// Attribute-specific interpretation is left to the caller.
    pub values_der_hex: Vec<String>,
}

/// Legacy Netscape certificate-type assertions, not enforced permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct NetscapeCertificateType {
    /// SSL client assertion.
    pub ssl_client: bool,
    /// SSL server assertion.
    pub ssl_server: bool,
    /// S/MIME assertion.
    pub smime: bool,
    /// Object signing assertion.
    pub object_signing: bool,
    /// Encoded reserved bit, retained without interpretation.
    pub reserved: bool,
    /// SSL certification-authority assertion.
    pub ssl_ca: bool,
    /// S/MIME certification-authority assertion.
    pub smime_ca: bool,
    /// Object-signing certification-authority assertion.
    pub object_signing_ca: bool,
}

pub(crate) fn decode(oid: &str, bytes: &[u8], names: &OidNames) -> Option<E> {
    Some(match oid {
        "2.5.29.30" => E::NameConstraints(crate::constraints::decode(bytes, names)?),
        "2.5.29.36" => {
            let p = pkix::PolicyConstraints::from_der(bytes).ok()?;
            if p.require_explicit_policy.is_none() && p.inhibit_policy_mapping.is_none() {
                return None;
            }
            E::PolicyConstraints(PolicyConstraints {
                require_explicit_policy: p.require_explicit_policy,
                inhibit_policy_mapping: p.inhibit_policy_mapping,
            })
        }
        "2.5.29.33" => {
            let p = pkix::PolicyMappings::from_der(bytes).ok()?;
            if p.0.is_empty() {
                return None;
            }
            E::PolicyMappings(
                p.0.iter()
                    .map(|m| {
                        let issuer_domain_policy = m.issuer_domain_policy.to_string();
                        let subject_domain_policy = m.subject_domain_policy.to_string();
                        PolicyMapping {
                            issuer_domain_policy_name: names
                                .get(&issuer_domain_policy)
                                .map(str::to_owned),
                            subject_domain_policy_name: names
                                .get(&subject_domain_policy)
                                .map(str::to_owned),
                            issuer_domain_policy,
                            subject_domain_policy,
                        }
                    })
                    .collect(),
            )
        }
        "2.5.29.54" => E::InhibitAnyPolicy(pkix::InhibitAnyPolicy::from_der(bytes).ok()?.0),
        "2.5.29.16" => {
            let p = pkix::PrivateKeyUsagePeriod::from_der(bytes).ok()?;
            if p.not_before.is_none() && p.not_after.is_none() {
                return None;
            }
            E::PrivateKeyUsagePeriod(PrivateKeyUsagePeriod {
                not_before_unix: p.not_before.map(|t| t.to_unix_duration().as_secs() as i64),
                not_after_unix: p.not_after.map(|t| t.to_unix_duration().as_secs() as i64),
            })
        }
        "2.5.29.9" => {
            let p = pkix::SubjectDirectoryAttributes::from_der(bytes).ok()?;
            if p.0.is_empty() {
                return None;
            }
            E::SubjectDirectoryAttributes(
                p.0.iter()
                    .map(|a| {
                        if a.values.is_empty() {
                            return None;
                        }
                        let oid = a.oid.to_string();
                        Some(DirectoryAttribute {
                            name: names.get(&oid).map(str::to_owned),
                            oid,
                            values_der_hex: a
                                .values
                                .iter()
                                .map(|v| Some(hex::encode(v.to_der().ok()?)))
                                .collect::<Option<Vec<_>>>()?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            )
        }
        "1.3.6.1.5.5.7.1.24" => {
            // RFC 7633 uses TLS ExtensionType numbers, not ASN.1 OIDs.
            let features = Vec::<u16>::from_der(bytes).ok()?;
            if features.is_empty() {
                return None;
            }
            E::TlsFeatures(features)
        }
        "1.3.6.1.5.5.7.48.1.5" => {
            Null::from_der(bytes).ok()?;
            E::OcspNoCheck
        }
        "1.3.6.1.4.1.11129.2.4.3" => {
            Null::from_der(bytes).ok()?;
            E::CtPoison
        }
        "2.16.840.1.113730.1.13" => {
            E::NetscapeComment(Ia5String::from_der(bytes).ok()?.as_str().into())
        }
        "2.16.840.1.113730.1.1" => {
            use x509_parser::prelude::FromDer;
            let bits = x509_cert::der::asn1::BitString::from_der(bytes).ok()?;
            let data = bits.raw_bytes();
            if data.len() != 1 {
                return None;
            }
            let (rest, n) = x509_parser::extensions::NSCertType::from_der(bytes).ok()?;
            if !rest.is_empty() {
                return None;
            }
            E::NetscapeCertificateType(NetscapeCertificateType {
                ssl_client: n.ssl_client(),
                ssl_server: n.ssl_server(),
                smime: n.smime(),
                object_signing: n.object_signing(),
                reserved: data[0] & 8 != 0,
                ssl_ca: n.ssl_ca(),
                smime_ca: n.smime_ca(),
                object_signing_ca: n.object_signing_ca(),
            })
        }
        "1.3.6.1.4.1.11129.2.4.2" => {
            E::SignedCertificateTimestamps(crate::transparency::decode(bytes)?)
        }
        _ => E::Unsupported,
    })
}
