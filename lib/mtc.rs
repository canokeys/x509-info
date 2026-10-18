//! Merkle Tree Certificate (MTC) structures from the IETF PLANTS draft.
//!
//! This covers inspection of draft-ietf-plants-merkle-tree-certs-07 wire formats
//! embedded in X.509 certificates: the MTCProof in the signature value, the
//! (log number, entry index) serial number split, and the MTCCertificationAuthority
//! CA extension. Wire-format parsing is delegated to the `mtcs` crate (no-default-features
//! base layer); this module maps it onto owned inspection types and diagnostics.
//! Inclusion proofs, cosignatures and landmarks are parsed and retained, never
//! verified; the draft's canonical cosigner ordering rule is a verifier concern
//! (`mtcs::MtcProof::parse_strict`) and is not enforced here.

use crate::{DecodeDiagnostic, OidNames};

/// Signature algorithm OID `id-alg-mtcProof`; its AlgorithmIdentifier omits parameters.
pub const MTC_PROOF_ALGORITHM_OID: &str = "1.3.6.1.5.5.7.6.67";
/// Attribute type OID `id-rdna-trustAnchorID`, carrying a RELATIVE-OID trust anchor ID.
pub const TRUST_ANCHOR_ID_ATTRIBUTE_OID: &str = "1.3.6.1.5.5.7.25.3";
/// Critical CA extension OID `id-pe-mtcCertificationAuthority-SHA256`.
pub const MTC_CA_SHA256_EXTENSION_OID: &str = "1.3.6.1.5.5.7.1.38";

/// One tag-length-value log entry extension, in proof encoding order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MtcEntryExtension {
    /// 16-bit MTCLogEntryExtensionType, including values unassigned by the draft.
    pub extension_type: u16,
    /// Opaque extension data octets.
    pub extension_data: Vec<u8>,
}

/// One subtree cosignature in a Merkle Tree certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MtcCosignature {
    /// Binary trust anchor ID of the cosigner (RELATIVE-OID content octets).
    /// Ordering and uniqueness are the verifier's concern and are not checked here.
    pub cosigner_id: Vec<u8>,
    /// Signature octets; no cryptographic verification is performed.
    pub signature: Vec<u8>,
}

impl MtcCosignature {
    /// The cosigner ID in dotted-decimal trust anchor ID notation, when the
    /// binary form is valid. Presentation only; the raw bytes are authoritative.
    pub fn cosigner_id_dotted(&self) -> Option<String> {
        mtcs::TrustAnchorId::from_binary(&self.cosigner_id)
            .ok()
            .map(|id| id.to_dotted())
    }
}

/// A decoded MTCProof structure from a certificate's signature value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MtcProof {
    /// Log entry extensions copied from the MTCLogEntry, in encoded order.
    pub entry_extensions: Vec<MtcEntryExtension>,
    /// Subtree interval start; the draft encodes it as a uint48.
    pub subtree_start: u64,
    /// Subtree interval end (exclusive); the draft encodes it as a uint48.
    pub subtree_end: u64,
    /// Concatenated subtree inclusion proof hashes; the hash width is the CA's
    /// configured algorithm parameter and is not assumed by this representation.
    pub inclusion_proof: Vec<u8>,
    /// Subtree cosignatures in encoded order; values are retained, not verified.
    pub cosignatures: Vec<MtcCosignature>,
}

/// The serial number of a Merkle Tree certificate, split into its log coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MtcEntryReference {
    /// Issuance log number; the draft requires it to be nonzero, which is not
    /// enforced by this inspection.
    pub log_number: u16,
    /// Zero-based entry index within the issuance log.
    pub entry_index: u64,
}

/// The decoded MTCCertificationAuthority extension of a Merkle Tree CA certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MtcCertificationAuthority {
    /// Dotted-decimal CA cosigner signature algorithm OID.
    pub signature_algorithm_oid: String,
    /// Common algorithm label, when recognized.
    pub signature_algorithm_name: Option<String>,
    /// Minimum allowed serial number as INTEGER content octets in lowercase hex.
    pub min_serial_hex: String,
    /// Maximum allowed serial number as INTEGER content octets in lowercase hex.
    pub max_serial_hex: String,
    /// Minimum serial as u64; None when the INTEGER exceeds the draft's u64 range.
    pub min_serial: Option<u64>,
    /// Maximum serial as u64; None when the INTEGER exceeds the draft's u64 range.
    pub max_serial: Option<u64>,
}

/// Parse the MTCProof wire format via the shared `mtcs` base layer. Structural
/// soundness is required; the draft's canonical cosigner ordering and uniqueness
/// rules are left to verifiers and are not enforced here.
pub(crate) fn parse_proof(bytes: &[u8]) -> Result<MtcProof, DecodeDiagnostic> {
    let proof = mtcs::MtcProof::parse(bytes).map_err(|_| DecodeDiagnostic::invalid("MTCProof"))?;
    Ok(MtcProof {
        entry_extensions: proof
            .entry_extensions
            .into_iter()
            .map(|(extension_type, extension_data)| MtcEntryExtension {
                extension_type,
                extension_data,
            })
            .collect(),
        subtree_start: proof.subtree.start,
        subtree_end: proof.subtree.end,
        inclusion_proof: proof.inclusion_proof,
        cosignatures: proof
            .cosignatures
            .into_iter()
            .map(|cosignature| MtcCosignature {
                cosigner_id: cosignature.cosigner_id,
                signature: cosignature.signature,
            })
            .collect(),
    })
}

/// Decode the MTCCertificationAuthority extension value via the shared `mtcs`
/// base layer, adding the caller's algorithm label where known.
pub(crate) fn decode_ca_extension(
    bytes: &[u8],
    names: &OidNames,
) -> Option<crate::ExtensionDetails> {
    let parameters = mtcs::parse_mtc_ca_parameters(bytes).ok()?;
    Some(crate::ExtensionDetails::MtcCertificationAuthority(
        MtcCertificationAuthority {
            signature_algorithm_name: names
                .get(&parameters.signature_algorithm_oid)
                .map(str::to_owned),
            signature_algorithm_oid: parameters.signature_algorithm_oid,
            min_serial_hex: hex::encode(&parameters.min_serial_content),
            min_serial: Some(parameters.min_serial),
            max_serial_hex: hex::encode(&parameters.max_serial_content),
            max_serial: Some(parameters.max_serial),
        },
    ))
}

impl crate::CertificateInfo {
    /// Decode the signature value as an MTCProof when the inner signature algorithm
    /// is `id-alg-mtcProof`. Returns None for other algorithms. A malformed proof,
    /// including a signature BIT STRING with padding bits, is a typed finding.
    /// Cosignatures and the inclusion proof are decoded, never verified.
    pub fn mtc_proof(&self) -> Option<Result<MtcProof, DecodeDiagnostic>> {
        if self.tbs_signature_algorithm.oid != MTC_PROOF_ALGORITHM_OID {
            return None;
        }
        if self.signature_unused_bits != 0 {
            return Some(Err(DecodeDiagnostic::new(
                crate::DecodeIssue::InvalidEncoding,
                "signature unused bits",
            )));
        }
        Some(parse_proof(&self.signature_value))
    }

    /// Split the serial number into issuance log coordinates when the inner
    /// signature algorithm is `id-alg-mtcProof`. Returns None for other algorithms
    /// and for negative or over-u64 serials, which cannot be MTC coordinates.
    pub fn mtc_entry_reference(&self) -> Option<MtcEntryReference> {
        if self.tbs_signature_algorithm.oid != MTC_PROOF_ALGORITHM_OID {
            return None;
        }
        mtcs::split_serial(&self.serial_number).map(|reference| MtcEntryReference {
            log_number: reference.log_number,
            entry_index: reference.entry_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_round_trips_minimal_and_populated_forms() {
        let minimal = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_proof(&minimal).unwrap(),
            MtcProof {
                entry_extensions: Vec::new(),
                subtree_start: 0,
                subtree_end: 0,
                inclusion_proof: Vec::new(),
                cosignatures: Vec::new(),
            }
        );
        let mut populated = Vec::new();
        populated.extend([0, 7, 0, 42, 0, 3, 1, 2, 3]); // extensions: type 42, 3 bytes
        populated.extend([0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 11]); // subtree [8, 11)
        populated.extend([0, 2, 170, 187]); // 2-byte inclusion proof
        populated.extend([0, 0, 11, 4, 129, 253, 89, 1, 0, 4, 9, 8, 7, 6]);
        let proof = parse_proof(&populated).unwrap();
        assert_eq!(
            proof.entry_extensions,
            [MtcEntryExtension {
                extension_type: 42,
                extension_data: vec![1, 2, 3],
            }]
        );
        assert_eq!((proof.subtree_start, proof.subtree_end), (8, 11));
        assert_eq!(proof.inclusion_proof, [170, 187]);
        assert_eq!(
            proof.cosignatures,
            [MtcCosignature {
                cosigner_id: vec![129, 253, 89, 1],
                signature: vec![9, 8, 7, 6],
            }]
        );
    }

    #[test]
    fn proof_rejects_truncation_trailing_and_empty_cosigner_ids() {
        let valid = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for n in 0..valid.len() {
            assert!(parse_proof(&valid[..n]).is_err(), "prefix {n}");
        }
        assert!(parse_proof(&[&valid[..], &[0]].concat()).is_err());
        // A cosigner ID of length zero is not a valid trust anchor ID.
        let empty_id = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0,
        ];
        assert!(parse_proof(&empty_id).is_err());
        // A length prefix exceeding the remaining input is structural damage.
        let overlong = [0, 4, 0, 1, 0];
        assert!(parse_proof(&overlong).is_err());
        // Unordered entry extensions are structural damage (they hash as a unit).
        let mut unordered = Vec::new();
        unordered.extend([0, 10, 0, 2, 0, 0, 0, 1, 0, 0]);
        unordered.extend([0; 17]);
        assert!(parse_proof(&unordered).is_err());
    }

    #[test]
    fn serial_split_handles_padding_and_range() {
        assert_eq!(
            mtcs::split_serial(&[1, 0, 0, 0, 0, 0, 10]).map(|r| (r.log_number, r.entry_index)),
            Some((1, 10))
        );
        // High log numbers require a sign-padding octet in DER.
        assert_eq!(
            mtcs::split_serial(&[0, 255, 255, 0, 0, 0, 0, 0, 0])
                .map(|r| (r.log_number, r.entry_index)),
            Some((65535, 0))
        );
        assert_eq!(mtcs::split_serial(&[]), None);
        assert_eq!(mtcs::split_serial(&[0x80]), None); // Negative.
        assert_eq!(mtcs::split_serial(&[1; 9]), None);
        assert_eq!(
            mtcs::split_serial(&[42]).map(|r| (r.log_number, r.entry_index)),
            Some((0, 42))
        );
    }
}
