use crate::OidNames;
use x509_cert::{
    der::{asn1::Ia5String, Decode, Encode},
    ext::pkix::CertificatePolicies,
};

/// One asserted certificate policy; OID recognition never implies policy compliance.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct CertificatePolicy {
    /// Dotted-decimal policy identifier, including unknown/private policies.
    pub oid: String,
    /// Presentation label from the caller's OID table, when available.
    pub name: Option<String>,
    /// Qualifiers in encoded order; empty when the optional sequence is absent.
    pub qualifiers: Vec<PolicyQualifier>,
}

/// Interpretation of a policy qualifier, without policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum PolicyQualifierDetails {
    /// CPS URI text. It is not validated as a URL and is never fetched.
    CpsUri(String),
    /// Structured notice text/reference; no policy compliance is inferred.
    UserNotice(UserNotice),
    /// Unknown qualifier; raw DER remains.
    Unparsed,
    /// A known qualifier could not be decoded within the supported representation.
    Malformed,
}

/// One policy qualifier with its original value representation retained.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct PolicyQualifier {
    /// Dotted-decimal qualifier identifier.
    pub oid: String,
    /// Complete qualifier value DER in lowercase hex, including tag/length.
    /// Retained in summaries too so unparsed notices/private qualifiers remain useful.
    pub value_der_hex: String,
    /// Decoded URI/notice or an explicit unparsed/malformed state.
    pub details: PolicyQualifierDetails,
}

pub(crate) fn decode(bytes: &[u8], names: &OidNames) -> Option<Vec<CertificatePolicy>> {
    let policies = CertificatePolicies::from_der(bytes).ok()?;
    if policies.0.is_empty() {
        return None;
    }
    policies
        .0
        .iter()
        .map(|p| {
            let oid = p.policy_identifier.to_string();
            let qualifiers = match p.policy_qualifiers.as_ref() {
                Some(list) if list.is_empty() => return None,
                Some(list) => list
                    .iter()
                    .map(|q| {
                        // RFC 5280 requires a qualifier value even though the backend type is optional.
                        let value = q.qualifier.as_ref()?.to_der().ok()?;
                        let oid = q.policy_qualifier_id.to_string();
                        let details = if oid == "1.3.6.1.5.5.7.2.1" {
                            match Ia5String::from_der(&value) {
                                Ok(s) => PolicyQualifierDetails::CpsUri(s.as_str().into()),
                                Err(_) => PolicyQualifierDetails::Malformed,
                            }
                        } else if oid == "1.3.6.1.5.5.7.2.2" {
                            match notice(&value) {
                                Ok(n) => PolicyQualifierDetails::UserNotice(n),
                                Err(_) => PolicyQualifierDetails::Malformed,
                            }
                        } else {
                            PolicyQualifierDetails::Unparsed
                        };
                        Some(PolicyQualifier {
                            oid,
                            value_der_hex: hex::encode(value),
                            details,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                None => Vec::new(),
            };
            Some(CertificatePolicy {
                name: names.get(&oid).map(str::to_owned),
                oid,
                qualifiers,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_qualifier_failures_and_unparsed_values_are_distinct() {
        // Policy 1.2 containing a CPS qualifier with a NULL value.
        let bytes = [
            0x30, 21, 0x30, 19, 6, 1, 42, 0x30, 14, 0x30, 12, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 5, 0,
        ];
        let names = OidNames::default();
        let result = decode(&bytes, &names).unwrap();
        assert_eq!(
            result[0].qualifiers[0].details,
            PolicyQualifierDetails::Malformed
        );
        assert_eq!(result[0].qualifiers[0].value_der_hex, "0500");
        let mut unknown = bytes;
        unknown[20] = 99;
        assert_eq!(
            decode(&unknown, &names).unwrap()[0].qualifiers[0].details,
            PolicyQualifierDetails::Unparsed
        );
        // A qualifier without its required ANY value must not become an empty result.
        let missing = [
            0x30, 19, 0x30, 17, 6, 1, 42, 0x30, 12, 0x30, 10, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1,
        ];
        assert!(decode(&missing, &names).is_none());
    }
}

/// Certificate-policy notice, preserving optional fields without display policy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct UserNotice {
    /// Organization and notice numbers, when encoded.
    pub notice_reference: Option<NoticeReference>,
    /// Explicit notice text, without sanitization or display-length enforcement.
    pub explicit_text: Option<String>,
}
/// Organization and referenced notice numbers; numbers are not range-checked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct NoticeReference {
    /// Decoded DisplayText organization string.
    pub organization: String,
    /// INTEGER values in encoded order, including negatives, repeats and large values.
    pub notice_numbers: Vec<crate::IntegerValue>,
}
fn notice(bytes: &[u8]) -> Result<UserNotice, crate::DecodeDiagnostic> {
    use crate::decoding::{any, children, integer, text};
    use x509_parser::asn1_rs::{Any, Tag};
    fn display(value: &Any<'_>) -> Result<String, crate::DecodeDiagnostic> {
        if !matches!(
            value.tag(),
            Tag::Ia5String | Tag::VisibleString | Tag::BmpString | Tag::Utf8String
        ) {
            return Err(crate::DecodeDiagnostic::new(
                crate::DecodeIssue::UnsupportedEncoding,
                "DisplayText choice",
            ));
        }
        text(value)
    }
    // x509-cert 0.3 models noticeRef as GeneralizedTime and omits two DisplayText
    // choices. Reuse generic ASN.1 decoding here to follow the actual RFC 5280 schema.
    let fields = children(&any(bytes)?, Tag::Sequence)?;
    let mut index = 0;
    let notice_reference = if fields.first().is_some_and(|f| f.tag() == Tag::Sequence) {
        let parts = children(&fields[0], Tag::Sequence)?;
        if parts.len() != 2 {
            return Err(crate::DecodeDiagnostic::invalid("NoticeReference fields"));
        }
        let organization = display(&parts[0])?;
        let notice_numbers = children(&parts[1], Tag::Sequence)?
            .iter()
            .map(integer)
            .collect::<Result<Vec<_>, _>>()?;
        index += 1;
        Some(NoticeReference {
            organization,
            notice_numbers,
        })
    } else {
        None
    };
    let explicit_text = fields.get(index).map(display).transpose()?;
    if explicit_text.is_some() {
        index += 1;
    }
    if index != fields.len() {
        return Err(crate::DecodeDiagnostic::invalid(
            "UserNotice trailing fields",
        ));
    }
    Ok(UserNotice {
        notice_reference,
        explicit_text,
    })
}
impl PolicyQualifier {
    /// Explain a known qualifier's decoding failure using its retained value DER.
    /// Unknown qualifier OIDs are reported as UnknownType, never guessed.
    pub fn diagnostic(&self) -> Option<crate::DecodeDiagnostic> {
        let bytes = match hex::decode(&self.value_der_hex) {
            Ok(b) => b,
            Err(_) => return Some(crate::DecodeDiagnostic::invalid("qualifier hex")),
        };
        match self.oid.as_str() {
            "1.3.6.1.5.5.7.2.2" => notice(&bytes).err(),
            "1.3.6.1.5.5.7.2.1" => Ia5String::from_der(&bytes)
                .err()
                .map(|e| crate::decoding::der_error(e, "CPS URI")),
            _ => Some(crate::DecodeDiagnostic::new(
                crate::DecodeIssue::UnknownType,
                "policy qualifier",
            )),
        }
    }
}
