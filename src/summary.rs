use crate::{
    AlgorithmInfo, CertificateInfo, DistinguishedName, ExtensionDetails, KeyDataStatus,
    NameAttribute, ParameterStatus, PssParameters, Validity,
};

/// Display-oriented name data without the complete Name DER.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct NameSummary {
    /// Presentation string, not a normalized identity.
    pub display: String,
    /// Ordered RDN groups with repeated and unknown attributes preserved.
    pub rdns: Vec<Vec<NameAttribute>>,
}
impl From<&DistinguishedName> for NameSummary {
    fn from(name: &DistinguishedName) -> Self {
        Self {
            display: name.display.clone(),
            rdns: name.rdns.clone(),
        }
    }
}

/// Algorithm description without raw parameter bytes; see AlgorithmInfo for full data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AlgorithmSummary {
    /// Dotted-decimal algorithm OID.
    pub oid: String,
    /// Recognized common label, or None.
    pub name: Option<String>,
    /// Parameter interpretation state; this is not a validation verdict.
    pub parameter_status: ParameterStatus,
    /// Decoded RSA-PSS parameters, when available.
    pub pss: Option<PssParameters>,
}
impl From<&AlgorithmInfo> for AlgorithmSummary {
    fn from(alg: &AlgorithmInfo) -> Self {
        Self {
            oid: alg.oid.clone(),
            name: alg.name.clone(),
            parameter_status: alg.parameter_status,
            pss: alg.pss.clone(),
        }
    }
}

/// Public-key description without key/SPKI bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PublicKeySummary {
    /// Algorithm and parameter description.
    pub algorithm: AlgorithmSummary,
    /// Supported key encoding status, independent of parameter status and trust.
    pub key_data_status: KeyDataStatus,
    /// Named-curve OID, when encoded as such.
    pub curve_oid: Option<String>,
    /// Recognized curve label, when available.
    pub curve_name: Option<String>,
    /// Modulus/nominal curve size, not a security-strength estimate.
    pub key_size_bits: Option<usize>,
}

/// Extension summary without raw extnValue bytes; unsupported values remain explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct ExtensionSummary {
    /// Dotted-decimal extension OID.
    pub oid: String,
    /// Encoded critical flag.
    pub critical: bool,
    /// Whether this OID occurs more than once in the certificate.
    pub duplicate: bool,
    /// Decoded fields, or an explicit unsupported/malformed state.
    pub details: ExtensionDetails,
}

/// Owned certificate details for UI/FFI and optional Serde export.
///
/// Schema version 1 uses lowercase unseparated hex for byte strings, signed Unix
/// seconds for times, dotted OIDs, null for absent/unknown values, and snake_case
/// tagged enums. Consumers must accept additional fields and unknown enum kinds.
/// Complete DER, signature, key and extension bytes are omitted; use CertificateInfo
/// for those. This summary is not a lossless certificate representation or trust verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct CertificateSummary {
    /// Serialization contract major version, currently 1 (separate from crate SemVer).
    pub schema_version: u32,
    /// One-based X.509 version.
    pub version: u32,
    /// Subject name and attributes.
    pub subject: NameSummary,
    /// Issuer name and attributes.
    pub issuer: NameSummary,
    /// Inclusive validity interval; no system clock is consulted.
    pub validity: Validity,
    /// Raw serial INTEGER content in lowercase hex, retaining sign padding.
    pub serial_number_hex: String,
    /// SHA-256 digest of the retained DER in lowercase hex.
    pub sha256_fingerprint_hex: String,
    /// Signature algorithm description.
    pub signature_algorithm: AlgorithmSummary,
    /// Public-key description.
    pub public_key: PublicKeySummary,
    /// Extensions in encoded order, including unsupported/malformed/duplicate entries.
    pub extensions: Vec<ExtensionSummary>,
}

impl CertificateInfo {
    /// Copy application-facing fields into an owned summary and compute SHA-256.
    /// Does not perform I/O or validation. The returned value outlives self and input.
    /// Mutating the public full-result fields before calling this changes the summary;
    /// derived fields are not re-parsed from DER. No result is cached.
    pub fn summary(&self) -> CertificateSummary {
        CertificateSummary {
            schema_version: 1,
            version: self.version,
            subject: (&self.subject).into(),
            issuer: (&self.issuer).into(),
            validity: self.validity,
            serial_number_hex: hex::encode(&self.serial_number),
            sha256_fingerprint_hex: hex::encode(self.sha256_fingerprint()),
            signature_algorithm: (&self.signature_algorithm).into(),
            public_key: PublicKeySummary {
                algorithm: (&self.public_key.algorithm).into(),
                key_data_status: self.public_key.key_data_status,
                curve_oid: self.public_key.curve_oid.clone(),
                curve_name: self.public_key.curve_name.clone(),
                key_size_bits: self.public_key.key_size_bits,
            },
            extensions: self
                .extensions
                .iter()
                .map(|e| ExtensionSummary {
                    oid: e.oid.clone(),
                    critical: e.critical,
                    duplicate: e.duplicate,
                    details: e.details.clone(),
                })
                .collect(),
        }
    }
}
