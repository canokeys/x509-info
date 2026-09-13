use crate::{
    extensions::general_name, names::inspect_attribute, GeneralName, NameAttribute, OidNames,
};
use x509_parser::extensions as backend;

/// Authority key identifier components, as asserted by the certificate.
/// Matching these fields does not establish an issuer relationship or trust.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AuthorityKeyIdentifier {
    /// Key identifier octets in lowercase hex, if present.
    pub key_identifier_hex: Option<String>,
    /// Issuer GeneralNames, if present, in encoded order.
    pub authority_cert_issuer: Option<Vec<GeneralName>>,
    /// Serial INTEGER content in lowercase hex, preserving sign padding.
    pub authority_cert_serial_hex: Option<String>,
}

/// An AIA/SIA access method and its location. This library never retrieves it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AccessDescription {
    /// Dotted-decimal method OID, including unrecognized methods.
    pub method_oid: String,
    /// Presentation label from the caller's OID table, when available.
    pub method_name: Option<String>,
    /// Encoded access location; not necessarily a URI or safe to fetch.
    pub location: GeneralName,
}

/// A CRL distribution-point name; relative RDNs are not resolved automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DistributionPointName {
    /// Full GeneralNames in encoded order.
    FullName(Vec<GeneralName>),
    /// One RDN relative to the CRL issuer, retaining all attributes.
    RelativeName(Vec<NameAttribute>),
}

/// A CRL/freshest-CRL distribution point, without revocation processing or I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DistributionPoint {
    /// Encoded distribution-point name, when present.
    pub name: Option<DistributionPointName>,
    /// ReasonFlags as a bit mask: bit 1 keyCompromise, 2 cACompromise,
    /// 3 affiliationChanged, 4 superseded, 5 cessationOfOperation,
    /// 6 certificateHold, 7 privilegeWithdrawn, 8 aACompromise; bit 0 is unused.
    /// None means no restriction was encoded. No revocation policy is inferred.
    pub reason_flags: Option<u16>,
    /// CRL issuer GeneralNames, if present.
    pub crl_issuer: Option<Vec<GeneralName>>,
}

pub(crate) fn access(
    items: &[backend::AccessDescription<'_>],
    names: &OidNames,
) -> Vec<AccessDescription> {
    items
        .iter()
        .map(|item| {
            let method_oid = item.access_method.to_id_string();
            AccessDescription {
                method_name: names.get(&method_oid).map(str::to_owned),
                method_oid,
                location: general_name(&item.access_location, names),
            }
        })
        .collect()
}

pub(crate) fn distribution(bytes: &[u8], names: &OidNames) -> Option<Vec<DistributionPoint>> {
    use x509_cert::{
        der::{Decode, Encode},
        ext::pkix::{name::DistributionPointName as B, CrlDistributionPoints},
    };
    use x509_parser::prelude::FromDer;
    let points = CrlDistributionPoints::from_der(bytes).ok()?;
    if points.0.is_empty() {
        return None;
    }
    points
        .0
        .iter()
        .map(|p| {
            let name = match p.distribution_point.as_ref() {
                Some(B::FullName(list)) => {
                    Some(DistributionPointName::FullName(crypto_names(list, names)?))
                }
                Some(B::NameRelativeToCRLIssuer(rdn)) => {
                    let der = rdn.to_der().ok()?;
                    let (rest, rdn) =
                        x509_parser::x509::RelativeDistinguishedName::from_der(&der).ok()?;
                    if !rest.is_empty() {
                        return None;
                    }
                    Some(DistributionPointName::RelativeName(
                        rdn.iter().map(|a| inspect_attribute(a, names)).collect(),
                    ))
                }
                None => None,
            };
            Some(DistributionPoint {
                name,
                reason_flags: p.reasons.map(|r| r.bits()),
                crl_issuer: match &p.crl_issuer {
                    Some(list) => Some(crypto_names(list, names)?),
                    None => None,
                },
            })
        })
        .collect()
}

fn crypto_names(
    list: &[x509_cert::ext::pkix::name::GeneralName],
    names: &OidNames,
) -> Option<Vec<GeneralName>> {
    use x509_cert::der::Encode;
    use x509_parser::prelude::FromDer;
    list.iter()
        .map(|item| {
            // Reuse the same GeneralName projection for both format libraries. Encoding
            // canonical in-memory values avoids duplicating string and IP conversion rules.
            let der = item.to_der().ok()?;
            let (rest, name) = backend::GeneralName::from_der(&der).ok()?;
            if !rest.is_empty() {
                return None;
            }
            Some(general_name(&name, names))
        })
        .collect()
}
