use x509_parser::asn1_rs::{Any, Class, FromDer, Tag};

/// Why a field could not be decoded; none of these categories is a trust verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DecodeIssue {
    /// Invalid structure, length, character encoding, or trailing data.
    InvalidEncoding,
    /// The field uses a recognized but unimplemented encoding/choice.
    UnsupportedEncoding,
    /// A backend cannot represent the encoded value or resource depth.
    RepresentationLimit,
    /// The OID/algorithm has no registered field decoder.
    UnknownType,
    /// An older backend path does not expose a more precise failure category.
    Unclassified,
}

/// Caller-owned field decoding diagnostic; not a certificate validation error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {issue:?}")]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct DecodeDiagnostic {
    /// Stable category suitable for matching without parsing Display text.
    pub issue: DecodeIssue,
    /// Field or encoding being inspected; contains no input data.
    pub field: String,
}
impl DecodeDiagnostic {
    pub(crate) fn new(issue: DecodeIssue, field: &str) -> Self {
        Self {
            issue,
            field: field.into(),
        }
    }
    pub(crate) fn invalid(field: &str) -> Self {
        Self::new(DecodeIssue::InvalidEncoding, field)
    }
}

/// ASN.1 INTEGER value without a machine-integer truncation or sign guess.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct IntegerValue {
    /// Complete two's-complement content octets in lowercase hex, retaining padding.
    pub content_hex: String,
    /// Value when representable as i64; None otherwise, with bytes still available.
    pub value: Option<i64>,
}

pub(crate) fn any(bytes: &[u8]) -> Result<Any<'_>, DecodeDiagnostic> {
    let (rest, value) = Any::from_der(bytes).map_err(|_| DecodeDiagnostic::invalid("DER"))?;
    if !rest.is_empty() {
        return Err(DecodeDiagnostic::invalid("trailing DER"));
    }
    Ok(value)
}
pub(crate) fn children<'a>(value: &Any<'a>, tag: Tag) -> Result<Vec<Any<'a>>, DecodeDiagnostic> {
    if value.class() != Class::Universal || value.tag() != tag || !value.header.is_constructed() {
        return Err(DecodeDiagnostic::invalid("sequence/set"));
    }
    let mut input = value.data;
    let mut result = Vec::new();
    while !input.is_empty() {
        let (rest, item) =
            Any::from_der(input).map_err(|_| DecodeDiagnostic::invalid("nested DER"))?;
        result.push(item);
        input = rest;
    }
    Ok(result)
}
pub(crate) fn integer(value: &Any<'_>) -> Result<IntegerValue, DecodeDiagnostic> {
    if value.class() != Class::Universal
        || value.tag() != Tag::Integer
        || value.header.is_constructed()
        || value.data.is_empty()
    {
        return Err(DecodeDiagnostic::invalid("INTEGER"));
    }
    // Reject redundant sign octets, but do not impose positivity or a value range.
    if value.data.len() > 1
        && ((value.data[0] == 0 && value.data[1] & 0x80 == 0)
            || (value.data[0] == 255 && value.data[1] & 0x80 != 0))
    {
        return Err(DecodeDiagnostic::invalid("INTEGER encoding"));
    }
    Ok(IntegerValue {
        content_hex: hex::encode(value.data),
        value: value.as_i64().ok(),
    })
}
pub(crate) fn text(value: &Any<'_>) -> Result<String, DecodeDiagnostic> {
    use x509_parser::asn1_rs::{
        Ia5String, NumericString, PrintableString, UniversalString, Utf8String, VisibleString,
    };
    if value.class() != Class::Universal || value.header.is_constructed() {
        return Err(DecodeDiagnostic::invalid("string tag"));
    }
    let bad = || DecodeDiagnostic::invalid("string encoding");
    match value.tag() {
        Tag::Utf8String => Utf8String::try_from(value)
            .map(|v| v.as_ref().to_owned())
            .map_err(|_| bad()),
        Tag::PrintableString => PrintableString::try_from(value)
            .map(|v| v.as_ref().to_owned())
            .map_err(|_| bad()),
        Tag::NumericString => NumericString::try_from(value)
            .map(|v| v.as_ref().to_owned())
            .map_err(|_| bad()),
        Tag::Ia5String => Ia5String::try_from(value)
            .map(|v| v.as_ref().to_owned())
            .map_err(|_| bad()),
        Tag::VisibleString => VisibleString::try_from(value)
            .map(|v| v.as_ref().to_owned())
            .map_err(|_| bad()),
        Tag::UniversalString => UniversalString::try_from(value)
            .map(|v| v.string())
            .map_err(|_| bad()),
        Tag::BmpString => x509_cert::der::asn1::BmpString::from_ucs2(value.data)
            .map(|v| v.to_string())
            .map_err(|_| bad()),
        _ => Err(DecodeDiagnostic::new(
            DecodeIssue::UnsupportedEncoding,
            "string tag",
        )),
    }
}

pub(crate) fn der_error(error: x509_cert::der::Error, field: &str) -> DecodeDiagnostic {
    use x509_cert::der::ErrorKind;
    let issue = match error.kind() {
        ErrorKind::Overlength | ErrorKind::NestingDepth => DecodeIssue::RepresentationLimit,
        ErrorKind::TagUnknown { .. } => DecodeIssue::UnsupportedEncoding,
        _ => DecodeIssue::InvalidEncoding,
    };
    DecodeDiagnostic::new(issue, field)
}

impl crate::ExtensionInfo {
    /// Explain an unsupported/malformed extension using retained bytes where possible.
    /// The legacy details enum is unchanged. Unclassified means the older decoding
    /// path discarded its cause; it must not be interpreted as proven invalid DER.
    /// No validity, critical-extension policy, or trust checks are performed.
    pub fn diagnostic(&self) -> Option<DecodeDiagnostic> {
        use crate::ExtensionDetails;
        if matches!(self.details, ExtensionDetails::Unsupported) {
            return Some(DecodeDiagnostic::new(
                DecodeIssue::UnknownType,
                "extension OID",
            ));
        }
        if !matches!(self.details, ExtensionDetails::Malformed) {
            return None;
        }
        if let Err(e) = crate::extensions::device::decode(&self.oid, &self.value_der) {
            return Some(e);
        }
        let value = match any(&self.value_der) {
            Ok(v) => v,
            Err(e) => return Some(e),
        };
        if self.oid == "2.5.29.54" {
            return Some(match integer(&value) {
                Ok(v)
                    if !value.data.is_empty()
                        && value.data[0] & 0x80 == 0
                        && v.value.is_none_or(|n| n > i64::from(u32::MAX)) =>
                {
                    DecodeDiagnostic::new(DecodeIssue::RepresentationLimit, "skipCerts u32")
                }
                _ => DecodeDiagnostic::invalid("skipCerts INTEGER"),
            });
        }
        if self.oid == "2.5.29.30" {
            use x509_cert::der::{Decode, ErrorKind, Tag, TagNumber};
            if let Err(e) = x509_cert::ext::pkix::NameConstraints::from_der(&self.value_der) {
                if matches!(
                    e.kind(),
                    ErrorKind::TagUnexpected {
                        actual: Tag::ContextSpecific {
                            number: TagNumber(3),
                            ..
                        },
                        ..
                    }
                ) {
                    return Some(DecodeDiagnostic::new(
                        DecodeIssue::UnsupportedEncoding,
                        "X.400 constraint",
                    ));
                }
                return Some(der_error(e, "name constraints"));
            }
        }
        Some(DecodeDiagnostic::new(
            DecodeIssue::Unclassified,
            "extension fields",
        ))
    }
}
