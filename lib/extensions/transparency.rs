use x509_cert::der::{asn1::OctetString, Decode};

/// One embedded SCT entry. No log lookup or signature verification is performed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum SctEntry {
    /// Decoded RFC 6962 v1 entry (wire version zero).
    V1(SignedCertificateTimestamp),
    /// An unrecognized version; preserve its entire entry without the u16 length.
    Unknown {
        /// Unrecognized wire version byte.
        version: u8,
        /// Complete entry, including version, in lowercase hex.
        encoded_hex: String,
    },
}

/// RFC 6962 v1 SCT fields, independent of the input certificate buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SignedCertificateTimestamp {
    /// 32-byte CT log identifier in lowercase hex; not a trusted log name.
    pub log_id_hex: String,
    /// Milliseconds since the Unix epoch, as encoded (unlike certificate seconds).
    pub timestamp_unix_ms: u64,
    /// Opaque SCT extension octets in lowercase hex.
    pub extensions_hex: String,
    /// TLS hash algorithm number, including unrecognized numbers.
    pub hash_algorithm: u8,
    /// TLS signature algorithm number, including unrecognized numbers.
    pub signature_algorithm: u8,
    /// Signature octets in lowercase hex; no cryptographic verification occurs.
    pub signature_hex: String,
}

// Bound each TLS vector before calling the backend, which otherwise ignores some
// unconsumed list/entry content. This reads framing only; SCT fields use its parser.
fn vector(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let header: [u8; 2] = input.get(..2)?.try_into().ok()?;
    let end = 2 + usize::from(u16::from_be_bytes(header));
    Some((input.get(end..)?, input.get(2..end)?))
}

pub(crate) fn decode(bytes: &[u8]) -> Option<Vec<SctEntry>> {
    let octets = OctetString::from_der(bytes).ok()?;
    let (rest, mut list) = vector(octets.as_bytes())?;
    if !rest.is_empty() || list.is_empty() {
        return None;
    }
    let mut entries = Vec::new();
    while !list.is_empty() {
        let (rest, entry) = vector(list)?;
        let version = *entry.first()?;
        entries.push(if version == 0 {
            let (remaining, value) =
                x509_parser::extensions::parse_ct_signed_certificate_timestamp(list).ok()?;
            // Fixed v1 fields occupy 47 bytes, plus the two variable byte vectors.
            if remaining.len() != rest.len()
                || entry.len() != 47 + value.extensions.0.len() + value.signature.data.len()
            {
                return None;
            }
            SctEntry::V1(SignedCertificateTimestamp {
                log_id_hex: hex::encode(value.id.key_id),
                timestamp_unix_ms: value.timestamp,
                extensions_hex: hex::encode(value.extensions.0),
                hash_algorithm: value.signature.hash_alg_id,
                signature_algorithm: value.signature.sign_alg_id,
                signature_hex: hex::encode(value.signature.data),
            })
        } else {
            SctEntry::Unknown {
                version,
                encoded_hex: hex::encode(entry),
            }
        });
        list = rest;
    }
    Some(entries)
}
