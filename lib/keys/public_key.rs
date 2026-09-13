use crate::{DecodeDiagnostic, DecodeIssue, PublicKeyInfo};
use pkcs1::der::Decode;
use sha2::{Digest, Sha256};

/// Parsed public-key fields. This performs no arithmetic or mathematical validation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum PublicKeyDetails {
    /// RSA INTEGER magnitudes; no primality, oddness, exponent, or strength checks.
    Rsa {
        /// Unsigned modulus octets in lowercase hex, excluding DER sign padding.
        modulus_hex: String,
        /// Unsigned public-exponent octets in lowercase hex, without a u64 limit.
        exponent_hex: String,
    },
    /// Uncompressed SEC1 point; coordinates are not checked against a curve.
    EcUncompressed {
        /// Fixed-width big-endian x coordinate in lowercase hex.
        x_hex: String,
        /// Fixed-width big-endian y coordinate in lowercase hex.
        y_hex: String,
    },
    /// Compressed SEC1 point; no decompression occurs.
    EcCompressed {
        /// Fixed-width big-endian x coordinate in lowercase hex.
        x_hex: String,
        /// Parity bit encoded by prefix 02/03.
        y_odd: bool,
    },
    /// RFC 8410 Ed25519/Ed448 encoded point, without point decoding/validation.
    Edwards(String),
    /// RFC 8410 X25519/X448 encoded u coordinate, retaining little-endian octets.
    Montgomery(String),
}
impl PublicKeyInfo {
    /// SHA-256 over the retained complete SPKI DER, including algorithm parameters.
    /// This identifies an encoding, not a mathematical key or trusted identity.
    pub fn spki_sha256_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.spki_der).into()
    }

    /// Parse fields from the retained key bytes. Results own their data and are not cached.
    /// Unknown algorithms return None. No parameter/curve/identity policy is evaluated.
    ///
    /// # Errors
    /// Returns a diagnostic for unsupported SEC1 choices, invalid framing/length,
    /// or non-octet-aligned supported key encodings. Raw key/SPKI bytes remain available.
    pub fn details(&self) -> Result<Option<PublicKeyDetails>, DecodeDiagnostic> {
        let oid = self.algorithm.oid.as_str();
        if !matches!(
            oid,
            "1.2.840.113549.1.1.1"
                | "1.2.840.113549.1.1.10"
                | "1.2.840.10045.2.1"
                | "1.3.101.110"
                | "1.3.101.111"
                | "1.3.101.112"
                | "1.3.101.113"
        ) {
            return Ok(None);
        }
        if self.key_bytes.len().checked_mul(8) != Some(self.encoded_key_bits) {
            return Err(DecodeDiagnostic::invalid("key BIT STRING unused bits"));
        }
        let bytes = &self.key_bytes;
        Ok(Some(match oid {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
                let key = pkcs1::RsaPublicKey::from_der(bytes)
                    .map_err(|_| DecodeDiagnostic::invalid("RSA public key"))?;
                PublicKeyDetails::Rsa {
                    modulus_hex: hex::encode(key.modulus.as_bytes()),
                    exponent_hex: hex::encode(key.public_exponent.as_bytes()),
                }
            }
            "1.2.840.10045.2.1" => match bytes.first() {
                Some(4) if bytes.len() > 1 && bytes.len() % 2 == 1 => {
                    let width = (bytes.len() - 1) / 2;
                    PublicKeyDetails::EcUncompressed {
                        x_hex: hex::encode(&bytes[1..1 + width]),
                        y_hex: hex::encode(&bytes[1 + width..]),
                    }
                }
                Some(2 | 3) if bytes.len() > 1 => PublicKeyDetails::EcCompressed {
                    x_hex: hex::encode(&bytes[1..]),
                    y_odd: bytes[0] == 3,
                },
                Some(2..=4) => return Err(DecodeDiagnostic::invalid("SEC1 coordinate framing")),
                _ => {
                    return Err(DecodeDiagnostic::new(
                        DecodeIssue::UnsupportedEncoding,
                        "SEC1 point choice",
                    ))
                }
            },
            "1.3.101.110" | "1.3.101.111" => PublicKeyDetails::Montgomery(hex::encode(bytes)),
            _ => PublicKeyDetails::Edwards(hex::encode(bytes)),
        }))
    }
}
