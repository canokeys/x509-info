use crate::{decoding, DecodeDiagnostic, ExtensionDetails as E, IntegerValue};
use x509_cert::der::{
    asn1::{BitString, BmpString, OctetString},
    Decode,
};
use x509_parser::asn1_rs::Tag;

/// FIDO U2F transport assertions. Unknown bits are retained; no transport is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct FidoTransports {
    /// Bluetooth Classic bit 0.
    pub bluetooth_classic: bool,
    /// Bluetooth Low Energy bit 1.
    pub bluetooth_low_energy: bool,
    /// USB bit 2.
    pub usb: bool,
    /// NFC bit 3.
    pub nfc: bool,
    /// Internal/USB-internal transport bit 4.
    pub internal: bool,
    /// Other set bit indices, counted from the first octet's most significant bit.
    pub unknown_bits: Vec<usize>,
    /// Complete bit-string content octets excluding unused-bit count, in lowercase hex.
    pub bits_hex: String,
    /// Number of unused bits in the last octet.
    pub unused_bits: u8,
}

/// Microsoft certificate-template fields without enrollment/template policy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct CertificateTemplate {
    /// Dotted-decimal template OID.
    pub template_oid: String,
    /// Optional major version as encoded; no DWORD range or sign policy is enforced.
    pub major_version: Option<IntegerValue>,
    /// Optional minor version as encoded.
    pub minor_version: Option<IntegerValue>,
}

pub(crate) fn decode(oid: &str, bytes: &[u8]) -> Result<Option<E>, DecodeDiagnostic> {
    Ok(Some(match oid {
        "1.3.6.1.4.1.45724.1.1.4" => {
            let value = OctetString::from_der(bytes)
                .map_err(|e| decoding::der_error(e, "AAGUID OCTET STRING"))?;
            // Preserve even an unusual length; comparing it to an authenticator's
            // AAGUID and enforcing the FIDO profile belong to the caller.
            E::FidoAaguid(hex::encode(value.as_bytes()))
        }
        "1.3.6.1.4.1.45724.2.1.1" => {
            let value = BitString::from_der(bytes)
                .map_err(|e| decoding::der_error(e, "FIDO transport BIT STRING"))?;
            let indices: Vec<_> = (0..value.bit_len())
                .filter(|&i| value.raw_bytes()[i / 8] & (0x80 >> (i % 8)) != 0)
                .collect();
            E::FidoTransports(FidoTransports {
                bluetooth_classic: indices.contains(&0),
                bluetooth_low_energy: indices.contains(&1),
                usb: indices.contains(&2),
                nfc: indices.contains(&3),
                internal: indices.contains(&4),
                unknown_bits: indices.into_iter().filter(|&n| n >= 5).collect(),
                bits_hex: hex::encode(value.raw_bytes()),
                unused_bits: value.unused_bits(),
            })
        }
        "1.3.6.1.4.1.311.20.2" => E::MicrosoftTemplateName(
            BmpString::from_der(bytes)
                .map_err(|e| decoding::der_error(e, "template BMPString"))?
                .to_string(),
        ),
        "1.3.6.1.4.1.311.21.7" => {
            let fields = decoding::children(&decoding::any(bytes)?, Tag::Sequence)?;
            if fields.is_empty() || fields.len() > 3 {
                return Err(DecodeDiagnostic::invalid("template fields"));
            }
            let oid = fields[0]
                .as_oid()
                .map_err(|_| DecodeDiagnostic::invalid("template OID"))?;
            E::MicrosoftCertificateTemplate(CertificateTemplate {
                template_oid: oid.to_id_string(),
                major_version: fields.get(1).map(decoding::integer).transpose()?,
                minor_version: fields.get(2).map(decoding::integer).transpose()?,
            })
        }
        _ => return Ok(None),
    }))
}
