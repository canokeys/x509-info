use crate::{extensions::general_name, GeneralName, OidNames};
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix,
};
use x509_parser::prelude::FromDer;

/// A name-constraint base. IP constraints encode an address and mask, not a host.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum ConstraintName {
    /// A non-IP GeneralName, interpreted as a constraint rather than an identity.
    Name(GeneralName),
    /// IPv4/IPv6 address and mask in textual notation; mask contiguity is not enforced.
    Ip {
        /// Address as encoded; host bits are not cleared.
        address: String,
        /// Mask as encoded; no CIDR prefix is inferred.
        mask: String,
    },
    /// IP constraint with an invalid length, retaining its octets in lowercase hex.
    MalformedIp(String),
}

/// One permitted/excluded subtree. This model does not evaluate name matching.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct GeneralSubtree {
    /// Name or address/mask base.
    pub base: ConstraintName,
    /// Encoded minimum distance, defaulting to zero. Nonzero values remain visible.
    pub minimum: u32,
    /// Optional maximum distance; no RFC 5280 policy is enforced.
    pub maximum: Option<u32>,
}

/// Encoded name constraints, with absent and present subtrees distinguished.
/// The strict backend supports u32 distances and GeneralNames except X.400;
/// values outside that representation yield a malformed extension finding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct NameConstraints {
    /// Permitted subtrees in encoded order, if present.
    pub permitted_subtrees: Option<Vec<GeneralSubtree>>,
    /// Excluded subtrees in encoded order, if present.
    pub excluded_subtrees: Option<Vec<GeneralSubtree>>,
}

pub(crate) fn decode(bytes: &[u8], names: &OidNames) -> Option<NameConstraints> {
    let value = pkix::NameConstraints::from_der(bytes).ok()?;
    if value.permitted_subtrees.is_none() && value.excluded_subtrees.is_none() {
        return None;
    }
    fn subtrees(
        list: Option<Vec<pkix::constraints::name::GeneralSubtree>>,
        names: &OidNames,
    ) -> Option<Option<Vec<GeneralSubtree>>> {
        let Some(list) = list else { return Some(None) };
        if list.is_empty() {
            return None;
        }
        let values = list
            .iter()
            .map(|item| {
                let base = match &item.base {
                    pkix::name::GeneralName::IpAddress(ip) => {
                        let bytes = ip.as_bytes();
                        match bytes.len() {
                            8 => ConstraintName::Ip {
                                address: std::net::Ipv4Addr::from(
                                    <[u8; 4]>::try_from(&bytes[..4]).ok()?,
                                )
                                .to_string(),
                                mask: std::net::Ipv4Addr::from(
                                    <[u8; 4]>::try_from(&bytes[4..]).ok()?,
                                )
                                .to_string(),
                            },
                            32 => ConstraintName::Ip {
                                address: std::net::Ipv6Addr::from(
                                    <[u8; 16]>::try_from(&bytes[..16]).ok()?,
                                )
                                .to_string(),
                                mask: std::net::Ipv6Addr::from(
                                    <[u8; 16]>::try_from(&bytes[16..]).ok()?,
                                )
                                .to_string(),
                            },
                            _ => ConstraintName::MalformedIp(hex::encode(bytes)),
                        }
                    }
                    value => {
                        let der = value.to_der().ok()?;
                        let (rest, parsed) =
                            x509_parser::extensions::GeneralName::from_der(&der).ok()?;
                        if !rest.is_empty() {
                            return None;
                        }
                        ConstraintName::Name(general_name(&parsed, names))
                    }
                };
                Some(GeneralSubtree {
                    base,
                    minimum: item.minimum,
                    maximum: item.maximum,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Some(values))
    }
    Some(NameConstraints {
        permitted_subtrees: subtrees(value.permitted_subtrees, names)?,
        excluded_subtrees: subtrees(value.excluded_subtrees, names)?,
    })
}
