//! Owned X.509 certificate inspection, independent of applets and transport.
//!
//! This extracts the reusable DER/PEM inspection responsibility from Console's
//! Rust `api/crypto.rs`. It uses the same `x509-parser` dependency, with owned
//! typed results and bounded, strict single-certificate inputs. Adapted extraction
//! code is covered by the upstream MIT notice in `LICENSE.console`; original
//! additions are Apache-2.0. Source provenance is recorded in the workspace docs.
//!
//! Parsing is not signature verification, chain building, trust, revocation, or
//! application policy. No system clock or randomness is read. The caller supplies
//! a timestamp to [`Validity::contains`] if it wants a validity-period check.
//! Unknown algorithm/extension OIDs and their encoded data remain available.
//!
//! [`CertificateInfo::summary`] provides owned application details, common decoded
//! extensions and a SHA-256 fingerprint without raw certificate/key/signature copies.
//! Enable `serde` for the versioned [`CertificateSummary`] serialization contract.
//! Full-result serialization remains available for diagnostics (raw bytes are octet
//! arrays). JSON belongs to callers; FRB can map these fields to its own DTOs.
//! No public result borrows backend types or requires a registry/handle lifecycle.
//!
//! # Example
//!
//! ```
//! use x509_info::{parse_pem, ParseOptions};
//! # let pem = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/inspection.pem"));
//! let info = parse_pem(pem, ParseOptions::default())?;
//! assert_eq!(info.public_key.key_size_bits, Some(256));
//! assert_eq!(info.public_key.algorithm.oid, "1.2.840.10045.2.1");
//! let details = info.summary();
//! drop(info);
//! let subject = details.subject; // Owned independently of parser input/results.
//! assert!(subject.display.contains("libcanokey test certificate"));
//! # Ok::<(), x509_info::Error>(())
//! ```
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod decoding;
mod extensions;
mod keys;
mod names;
mod oids;
mod summary;
#[cfg(test)]
mod tests;

pub use decoding::{DecodeDiagnostic, DecodeIssue, IntegerValue};
pub use extensions::additional::{
    DirectoryAttribute, NetscapeCertificateType, PolicyConstraints, PolicyMapping,
    PrivateKeyUsagePeriod,
};
pub use extensions::constraints::{ConstraintName, GeneralSubtree, NameConstraints};
pub use extensions::device::{CertificateTemplate, FidoTransports};
pub use extensions::locations::{
    AccessDescription, AuthorityKeyIdentifier, DistributionPoint, DistributionPointName,
};
pub use extensions::policies::{
    CertificatePolicy, NoticeReference, PolicyQualifier, PolicyQualifierDetails, UserNotice,
};
pub use extensions::transparency::{SctEntry, SignedCertificateTimestamp};
pub use extensions::{ExtensionDetails, ExtensionInfo, GeneralName, KeyPurpose, KeyUsage};
pub use keys::public_key::PublicKeyDetails;
pub use keys::{AlgorithmInfo, KeyDataStatus, ParameterStatus, PssParameters};
pub use names::details::NameDetails;
pub use names::{DistinguishedName, NameAttribute};
pub use oids::{InvalidOid, OidNames};
pub use summary::{
    AlgorithmSummary, CertificateSummary, ExtensionSummary, NameSummary, PublicKeySummary,
};

use sha2::{Digest, Sha256};
use x509_parser::nom::Parser;

impl CertificateInfo {
    /// SHA-256 digest of the retained certificate DER; no trust decision is implied.
    /// This recomputes the digest from the current bytes, without caching or global state.
    pub fn sha256_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }
}

/// Limits for a single certificate input; defaults to 1 MiB.
#[derive(Clone, Copy, Debug)]
pub struct ParseOptions {
    /// Maximum input bytes, also checked against decoded DER for PEM input.
    /// PEM limits include its armor, base64 and surrounding whitespace.
    pub max_input_bytes: usize,
}
impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
        }
    }
}

/// Typed local parsing failures, distinct from card status and transport errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A zero parsing budget was supplied.
    #[error("certificate input limit must be nonzero")]
    InvalidOptions,
    /// Encoded input or decoded DER exceeds the caller's budget.
    #[error("certificate input limit exceeded")]
    LimitExceeded,
    /// PEM armor/base64 is invalid, or input contains extra text/blocks.
    #[error("invalid certificate PEM")]
    InvalidPem,
    /// The PEM label is not CERTIFICATE.
    #[error("expected a CERTIFICATE PEM block")]
    UnexpectedPemLabel,
    /// Input could not be decoded as an X.509 certificate.
    #[error("invalid X.509 certificate")]
    InvalidCertificate,
    /// Bytes follow the single DER certificate.
    #[error("trailing data after certificate")]
    TrailingData,
    /// Legacy error retained for compatibility; parsing now preserves both identifiers.
    #[error("certificate signature algorithm identifiers disagree")]
    InconsistentSignatureAlgorithm,
}

/// Certificate validity interval as signed Unix seconds, independent of a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Validity {
    /// Inclusive notBefore timestamp, measured from 1970-01-01T00:00:00Z.
    pub not_before_unix: i64,
    /// Inclusive notAfter timestamp, measured from 1970-01-01T00:00:00Z.
    pub not_after_unix: i64,
}
impl Validity {
    /// Check only the inclusive time interval at an explicit caller timestamp.
    /// This does not establish certificate trust, role, revocation or signature validity.
    pub fn contains(self, unix_seconds: i64) -> bool {
        self.not_before_unix <= unix_seconds && unix_seconds <= self.not_after_unix
    }
}

/// Owned public-key algorithm and encoding, without performing key validation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PublicKeyInfo {
    /// Algorithm name, OID and parameter inspection.
    pub algorithm: AlgorithmInfo,
    /// Whether supported key encoding was decoded; no mathematical validation is performed.
    pub key_data_status: KeyDataStatus,
    /// Common named-curve label, when recognized.
    pub curve_name: Option<String>,
    /// Named-curve parameter OID when encoded as an OID; otherwise absent.
    pub curve_oid: Option<String>,
    /// RSA modulus bit length or nominal size of a recognized EC/EdDSA curve.
    /// None for unknown algorithms/curves or undecodable key data. This does not
    /// validate the key and is never replaced with the encoded bit-string length.
    pub key_size_bits: Option<usize>,
    /// Number of significant bits in the encoded subjectPublicKey BIT STRING.
    /// Distinct from a curve size, modulus size or security-strength estimate.
    pub encoded_key_bits: usize,
    /// Complete SubjectPublicKeyInfo DER, including algorithm parameters.
    pub spki_der: Vec<u8>,
    /// SubjectPublicKey BIT STRING bytes without its unused-bit count prefix.
    pub key_bytes: Vec<u8>,
}

/// Owned certificate inspection result; no input lifetime or device state.
///
/// Fields describe parsed data, not a trusted identity. The original DER remains
/// available for consumers that need richer policy/extension processing.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct CertificateInfo {
    /// Outer signature algorithm with decoded parameters where supported.
    pub signature_algorithm: AlgorithmInfo,
    /// Signature algorithm from TBSCertificate, retained independently of the outer field.
    pub tbs_signature_algorithm: AlgorithmInfo,
    /// Complete certificate DER, with no trailing object metadata or other certificate.
    pub der: Vec<u8>,
    /// One-based X.509 version (1, 2 or 3 for standard versions).
    pub version: u32,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Issuer distinguished name; not evidence of a verified issuer relationship.
    pub issuer: DistinguishedName,
    /// Encoded validity period; evaluating it requires a caller timestamp.
    pub validity: Validity,
    /// Original serial INTEGER content bytes, retaining any leading sign-padding byte.
    pub serial_number: Vec<u8>,
    /// Signature BIT STRING bytes without its unused-bit count prefix.
    pub signature_value: Vec<u8>,
    /// Number of unused bits in the final signature byte.
    pub signature_unused_bits: u8,
    /// Encoded public-key information and any recognized key size.
    pub public_key: PublicKeyInfo,
    /// Extensions in encoded order, with common decoded values; no policy is enforced.
    pub extensions: Vec<ExtensionInfo>,
}
impl std::fmt::Debug for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateInfo")
            .field("version", &self.version)
            .field("signature_algorithm_oid", &self.signature_algorithm.oid)
            .finish_non_exhaustive()
    }
}

fn check_limit(bytes: &[u8], options: ParseOptions) -> Result<(), Error> {
    if options.max_input_bytes == 0 {
        return Err(Error::InvalidOptions);
    }
    if bytes.len() > options.max_input_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}

/// Inspect exactly one DER certificate, copying its fields into an owned result.
///
/// PIV callers pass `certificate.der()` after the applet has unwrapped its object;
/// this function does not interpret PIV tags, decompress gzip or access a device.
///
/// # Errors
/// Returns InvalidOptions for a zero budget, LimitExceeded before parsing an
/// oversized input, InvalidCertificate for decoding failures, TrailingData if any
/// bytes follow the certificate. Inner/outer signature algorithms are retained independently.
/// Syntactic parsing does not verify signatures, key points, extensions or trust.
pub fn parse_der(bytes: &[u8], options: ParseOptions) -> Result<CertificateInfo, Error> {
    check_limit(bytes, options)?;
    parse_der_with_names(bytes, options, &OidNames::default())
}

/// Inspect one DER certificate using a caller-owned OID name table.
/// Results copy names and do not retain the table. Overrides affect presentation
/// only, never decoder selection, key sizes or validation.
///
/// # Errors
/// Returns the same input/syntax errors as [`parse_der`].
pub fn parse_der_with_names(
    bytes: &[u8],
    options: ParseOptions,
    names: &OidNames,
) -> Result<CertificateInfo, Error> {
    check_limit(bytes, options)?;
    let (rest, cert) = x509_parser::certificate::X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(bytes)
        .map_err(|_| Error::InvalidCertificate)?;
    if !rest.is_empty() {
        return Err(Error::TrailingData);
    }
    let spki = cert.public_key();
    let encoded_key_bits = spki
        .subject_public_key
        .data
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(usize::from(spki.subject_public_key.unused_bits)))
        .ok_or(Error::InvalidCertificate)?;
    let algorithm_oid = spki.algorithm.algorithm.to_id_string();
    let curve_oid = if algorithm_oid == "1.2.840.10045.2.1" {
        spki.algorithm
            .parameters
            .as_ref()
            .filter(|parameters| {
                parameters.class() == x509_parser::asn1_rs::Class::Universal
                    && parameters.tag() == x509_parser::asn1_rs::Tag::Oid
            })
            .and_then(|parameters| parameters.as_oid().ok())
            .map(|oid| oid.to_id_string())
    } else {
        None
    };
    let (key_size_bits, key_data_status) = keys::key_details(
        &algorithm_oid,
        curve_oid.as_deref(),
        &spki.subject_public_key.data,
        spki.subject_public_key.unused_bits,
    );
    let mut counts = std::collections::BTreeMap::new();
    for extension in cert.extensions() {
        *counts.entry(extension.oid.to_id_string()).or_insert(0usize) += 1;
    }
    Ok(CertificateInfo {
        signature_algorithm: keys::inspect(&cert.signature_algorithm, true, names)?,
        tbs_signature_algorithm: keys::inspect(&cert.tbs_certificate.signature, true, names)?,
        der: bytes.to_vec(),
        version: cert
            .version()
            .0
            .checked_add(1)
            .ok_or(Error::InvalidCertificate)?,
        subject: names::inspect_name(cert.subject(), names),
        issuer: names::inspect_name(cert.issuer(), names),
        validity: Validity {
            not_before_unix: cert.validity().not_before.timestamp(),
            not_after_unix: cert.validity().not_after.timestamp(),
        },
        serial_number: cert.raw_serial().to_vec(),
        signature_value: cert.signature_value.data.to_vec(),
        signature_unused_bits: cert.signature_value.unused_bits,
        public_key: PublicKeyInfo {
            algorithm: keys::inspect(&spki.algorithm, false, names)?,
            curve_name: curve_oid
                .as_deref()
                .and_then(|oid| names.get(oid))
                .map(str::to_owned),
            curve_oid,
            key_size_bits,
            key_data_status,
            encoded_key_bits,
            spki_der: spki.raw.to_vec(),
            key_bytes: spki.subject_public_key.data.to_vec(),
        },
        extensions: cert
            .extensions()
            .iter()
            .map(|extension| ExtensionInfo {
                oid: extension.oid.to_id_string(),
                critical: extension.critical,
                duplicate: counts[&extension.oid.to_id_string()] > 1,
                details: extensions::decode_with_names(
                    &extension.oid.to_id_string(),
                    extension.value,
                    names,
                ),
                value_der: extension.value.to_vec(),
            })
            .collect(),
    })
}

/// Inspect one CERTIFICATE PEM block, permitting only surrounding ASCII whitespace.
///
/// Input is bounded before base64 decoding. Bundles, unrelated labels, and text
/// before/after the block are rejected rather than silently selecting one entry.
/// Decoded DER is checked with [`parse_der`]. No file or system I/O occurs.
///
/// # Errors
/// Returns InvalidOptions/LimitExceeded for budgets, InvalidPem for invalid armor,
/// UnexpectedPemLabel for another block type, InvalidPem for extra PEM blocks/data,
/// or an error from [`parse_der`] for the decoded certificate.
pub fn parse_pem(bytes: &[u8], options: ParseOptions) -> Result<CertificateInfo, Error> {
    check_limit(bytes, options)?;
    parse_pem_with_names(bytes, options, &OidNames::default())
}

/// Inspect one PEM certificate with caller-owned presentation names.
/// The input and name table are borrowed only for this call; output owns all data.
///
/// # Errors
/// Returns the same budget, armor and certificate errors as [`parse_pem`].
pub fn parse_pem_with_names(
    bytes: &[u8],
    options: ParseOptions,
    names: &OidNames,
) -> Result<CertificateInfo, Error> {
    check_limit(bytes, options)?;
    let trimmed = bytes.trim_ascii();
    // RFC 7468 decoding validates matching boundaries and full consumption.
    // Unlike Console's former PEM helper, no extra block/text is silently ignored.
    let (label, der) = pem_rfc7468::decode_vec(trimmed).map_err(|_| Error::InvalidPem)?;
    if label != "CERTIFICATE" {
        return Err(Error::UnexpectedPemLabel);
    }
    parse_der_with_names(&der, options, names)
}
