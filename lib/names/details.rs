use crate::{decoding, DecodeDiagnostic, DecodeIssue, GeneralName};
use x509_cert::der::{asn1::Any as DerAny, Decode, Encode, Tag as DerTag};
use x509_parser::asn1_rs::{Class, Tag};

/// Additional fields decoded from a GeneralName's retained encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum NameDetails {
    /// Microsoft user principal name, without account lookup or name validation.
    UserPrincipalName(String),
    /// RFC 4985 DNS SRV name, without service/domain validation.
    DnsSrv(String),
    /// RFC 6120 XMPP address, without address validation.
    XmppAddress(String),
    /// RFC 4108 hardware identifier, without matching a physical device.
    HardwareModule {
        /// Dotted-decimal hardware type identifier.
        type_oid: String,
        /// Hardware serial number octets in lowercase hex.
        serial_hex: String,
    },
    /// EDI party name; no organization/party identity matching occurs.
    EdiPartyName {
        /// Name assigner when encoded.
        name_assigner: Option<String>,
        /// Required party name.
        party_name: String,
    },
}

impl GeneralName {
    /// Decode common OtherName/EDI fields from this owned value's retained bytes.
    /// Returns None for other choices or unknown OtherName OIDs. No input is retained.
    /// Raw encodings stay available regardless of the result; no value is cached.
    ///
    /// # Errors
    /// Reports invalid wrappers/strings, unsupported encodings, or backend limits.
    /// These diagnostics concern field decoding, not certificate or identity validity.
    pub fn details(&self) -> Result<Option<NameDetails>, DecodeDiagnostic> {
        match self {
            GeneralName::OtherName {
                oid, value_der_hex, ..
            } => {
                if !matches!(
                    oid.as_str(),
                    "1.3.6.1.4.1.311.20.2.3"
                        | "1.3.6.1.5.5.7.8.4"
                        | "1.3.6.1.5.5.7.8.5"
                        | "1.3.6.1.5.5.7.8.7"
                ) {
                    return Ok(None);
                }
                let bytes = hex::decode(value_der_hex)
                    .map_err(|_| DecodeDiagnostic::invalid("OtherName hex"))?;
                let wrapper = decoding::any(&bytes)?;
                if wrapper.class() != Class::ContextSpecific
                    || wrapper.tag().0 != 0
                    || !wrapper.header.is_constructed()
                {
                    return Err(DecodeDiagnostic::invalid("OtherName explicit value"));
                }
                if oid == "1.3.6.1.5.5.7.8.4" {
                    let h = x509_cert::ext::pkix::name::HardwareModuleName::from_der(wrapper.data)
                        .map_err(|e| decoding::der_error(e, "HardwareModuleName"))?;
                    return Ok(Some(NameDetails::HardwareModule {
                        type_oid: h.hw_type.to_string(),
                        serial_hex: hex::encode(h.hw_serial_num.as_bytes()),
                    }));
                }
                let value = decoding::any(wrapper.data)?;
                let expected = if oid == "1.3.6.1.5.5.7.8.7" {
                    Tag::Ia5String
                } else {
                    Tag::Utf8String
                };
                if value.tag() != expected {
                    return Err(DecodeDiagnostic::invalid("OtherName string type"));
                }
                let text = decoding::text(&value)?;
                Ok(Some(match oid.as_str() {
                    "1.3.6.1.4.1.311.20.2.3" => NameDetails::UserPrincipalName(text),
                    "1.3.6.1.5.5.7.8.7" => NameDetails::DnsSrv(text),
                    _ => NameDetails::XmppAddress(text),
                }))
            }
            GeneralName::EdiPartyName {
                constructed,
                content_hex,
            } => {
                if !constructed {
                    return Err(DecodeDiagnostic::invalid("EDI constructed bit"));
                }
                let content =
                    hex::decode(content_hex).map_err(|_| DecodeDiagnostic::invalid("EDI hex"))?;
                let der = DerAny::new(DerTag::Sequence, content)
                    .and_then(|v| v.to_der())
                    .map_err(|e| decoding::der_error(e, "EDI encoding"))?;
                let value = x509_cert::ext::pkix::name::EdiPartyName::from_der(&der)
                    .map_err(|e| decoding::der_error(e, "EDI fields"))?;
                Ok(Some(NameDetails::EdiPartyName {
                    name_assigner: value.name_assigner.map(|v| v.value().into_owned()),
                    party_name: value.party_name.value().into_owned(),
                }))
            }
            GeneralName::X400Address { .. } => Err(DecodeDiagnostic::new(
                DecodeIssue::UnsupportedEncoding,
                "X.400 fields",
            )),
            GeneralName::Malformed(_) => Err(DecodeDiagnostic::invalid("GeneralName")),
            _ => Ok(None),
        }
    }
}

impl crate::DirectoryAttribute {
    /// Decode string-valued attribute members individually, in their original order.
    /// Unsupported/non-string values return diagnostics and retain their original DER.
    /// No attribute-specific syntax, identity matching, or policy is enforced.
    pub fn text_values(&self) -> Vec<Result<String, DecodeDiagnostic>> {
        self.values_der_hex
            .iter()
            .map(|raw| {
                let bytes = hex::decode(raw)
                    .map_err(|_| DecodeDiagnostic::invalid("attribute value hex"))?;
                decoding::text(&decoding::any(&bytes)?)
            })
            .collect()
    }
}
