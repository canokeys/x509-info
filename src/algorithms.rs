use crate::Error;
use pkcs1::der::Decode;
use x509_parser::{asn1_rs::ToDer, x509::AlgorithmIdentifier};

/// Parameter inspection state, separate from algorithm recognition and trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ParameterStatus {
    /// No parameters were encoded; does not imply they may legally be absent.
    Absent,
    /// Parameters were decoded within the documented supported representation.
    Decoded,
    /// Encoded parameters are retained but not interpreted by this library.
    Unparsed,
    /// Parameters violate a checked encoding rule or exceed the decoder's representation.
    /// For PSS, pkcs1 currently supports salt lengths up to 255 and trailer field 1.
    DecodeError,
}

/// Decoded RSA-PSS parameters, including RFC 8017 defaults.
/// No assertion is made that the parameters are secure or usable with a given key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct PssParameters {
    /// Dotted-decimal message hash OID (SHA-1 when defaulted).
    pub hash_oid: String,
    /// Dotted-decimal mask-generation algorithm OID (MGF1 when defaulted).
    pub mask_gen_oid: String,
    /// MGF1 hash OID, if the mask-generation algorithm is MGF1 and includes it.
    pub mask_gen_hash_oid: Option<String>,
    /// Salt length in octets, including the default of 20.
    pub salt_length: u32,
    /// Trailer field, currently 1; other values produce DecodeError.
    pub trailer_field: u32,
}

/// Algorithm information with an optional common label and preserved parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AlgorithmInfo {
    /// Dotted-decimal algorithm OID; always retained even if unrecognized.
    pub oid: String,
    /// Common algorithm label. Recognition does not imply validity or support for use.
    pub name: Option<String>,
    /// DER encoding of parameters, when present. Original certificate DER is retained too.
    pub parameters_der: Option<Vec<u8>>,
    /// Whether the parameters were absent, decoded, unparsed or failed decoding.
    pub parameter_status: ParameterStatus,
    /// Decoded RSA-PSS parameters, when available.
    pub pss: Option<PssParameters>,
}

pub(crate) fn curve_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.840.10045.3.1.7" => Some("P-256"),
        "1.3.132.0.34" => Some("P-384"),
        "1.3.132.0.35" => Some("P-521"),
        "1.3.132.0.10" => Some("secp256k1"),
        "1.2.156.10197.1.301" => Some("SM2"),
        _ => None,
    }
}

pub(crate) fn inspect(
    alg: &AlgorithmIdentifier<'_>,
    signature: bool,
) -> Result<AlgorithmInfo, Error> {
    let oid = alg.algorithm.to_id_string();
    let name = match oid.as_str() {
        "1.2.840.113549.1.1.1" => Some("RSA"),
        "1.2.840.113549.1.1.10" => Some("RSA-PSS"),
        "1.2.840.10045.2.1" => Some("EC"),
        "1.3.101.112" => Some("Ed25519"),
        "1.3.101.113" => Some("Ed448"),
        "1.2.840.113549.1.1.5" => Some("RSA-SHA1"),
        "1.2.840.113549.1.1.11" => Some("RSA-SHA256"),
        "1.2.840.113549.1.1.12" => Some("RSA-SHA384"),
        "1.2.840.113549.1.1.13" => Some("RSA-SHA512"),
        "1.2.840.10045.4.1" => Some("ECDSA-SHA1"),
        "1.2.840.10045.4.3.2" => Some("ECDSA-SHA256"),
        "1.2.840.10045.4.3.3" => Some("ECDSA-SHA384"),
        "1.2.840.10045.4.3.4" => Some("ECDSA-SHA512"),
        _ => None,
    }
    .map(str::to_owned);
    let parameters_der = alg
        .parameters
        .as_ref()
        .map(|p| p.to_der_vec().map_err(|_| Error::InvalidCertificate))
        .transpose()?;
    let mut parameter_status = if parameters_der.is_some() {
        ParameterStatus::Unparsed
    } else {
        ParameterStatus::Absent
    };
    let mut pss = None;
    if oid == "1.2.840.113549.1.1.10" {
        if let Some(bytes) = parameters_der.as_deref() {
            match pkcs1::RsaPssParams::from_der(bytes) {
                Ok(p) => {
                    let mask_gen_oid = p.mask_gen.oid.to_string();
                    let mask_gen_hash_oid = if mask_gen_oid == "1.2.840.113549.1.1.8" {
                        p.mask_gen.parameters.as_ref().map(|a| a.oid.to_string())
                    } else {
                        None
                    };
                    parameter_status = ParameterStatus::Decoded;
                    pss = Some(PssParameters {
                        hash_oid: p.hash.oid.to_string(),
                        mask_gen_oid,
                        mask_gen_hash_oid,
                        salt_length: u32::from(p.salt_len),
                        trailer_field: p.trailer_field as u32,
                    });
                }
                Err(_) => parameter_status = ParameterStatus::DecodeError,
            }
        } else if signature {
            // PSS SPKI parameters may be absent (unrestricted key); signature parameters may not.
            parameter_status = ParameterStatus::DecodeError;
        }
    } else if matches!(oid.as_str(), "1.3.101.112" | "1.3.101.113") && parameters_der.is_some() {
        parameter_status = ParameterStatus::DecodeError;
    }
    if oid == "1.2.840.10045.2.1" {
        parameter_status = match alg.parameters.as_ref() {
            Some(p)
                if p.class() == x509_parser::asn1_rs::Class::Universal && p.as_oid().is_ok() =>
            {
                ParameterStatus::Decoded
            }
            Some(_) => ParameterStatus::Unparsed, // Explicit EC parameters are retained, not interpreted.
            None => ParameterStatus::DecodeError,
        };
    }
    Ok(AlgorithmInfo {
        oid,
        name,
        parameters_der,
        parameter_status,
        pss,
    })
}

pub(crate) fn rsa_bits(bytes: &[u8]) -> Option<usize> {
    let key = pkcs1::RsaPublicKey::from_der(bytes).ok()?;
    let modulus = key.modulus.as_bytes();
    let first = modulus.iter().position(|b| *b != 0)?;
    Some((modulus.len() - first) * 8 - modulus[first].leading_zeros() as usize)
}

/// Inspection state for public-key bytes, separate from algorithm parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum KeyDataStatus {
    /// The algorithm or curve has no supported key representation here.
    Unparsed,
    /// Supported encoding/length was decoded; mathematical key validity is not checked.
    Decoded,
    /// A supported key encoding has invalid structure, length or unused bits.
    DecodeError,
}

pub(crate) fn key_details(
    oid: &str,
    curve: Option<&str>,
    bytes: &[u8],
    unused: u8,
) -> (Option<usize>, KeyDataStatus) {
    let decoded = |bits| (Some(bits), KeyDataStatus::Decoded);
    let failed = (None, KeyDataStatus::DecodeError);
    match oid {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            if unused != 0 {
                return failed;
            }
            rsa_bits(bytes).map(decoded).unwrap_or(failed)
        }
        "1.3.101.112" => {
            if bytes.len() == 32 && unused == 0 {
                decoded(255)
            } else {
                failed
            }
        }
        "1.3.101.113" => {
            if bytes.len() == 57 && unused == 0 {
                decoded(448)
            } else {
                failed
            }
        }
        "1.2.840.10045.2.1" => {
            let bits: usize = match curve {
                Some("1.2.840.10045.3.1.7" | "1.3.132.0.10" | "1.2.156.10197.1.301") => 256,
                Some("1.3.132.0.34") => 384,
                Some("1.3.132.0.35") => 521,
                _ => return (None, KeyDataStatus::Unparsed),
            };
            let width = bits.div_ceil(8);
            // Only SEC1 compressed/uncompressed encodings; no curve arithmetic.
            let expected = match bytes.first() {
                Some(2 | 3) => 1 + width,
                Some(4) => 1 + 2 * width,
                _ => return failed,
            };
            if bytes.len() == expected && unused == 0 {
                decoded(bits)
            } else {
                failed
            }
        }
        _ => (None, KeyDataStatus::Unparsed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::asn1_rs::{Any, FromDer, Oid};

    fn pss(params: Option<&[u8]>, signature: bool) -> AlgorithmInfo {
        let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 10]).unwrap();
        let params = params.map(|p| Any::from_der(p).unwrap().1);
        inspect(&AlgorithmIdentifier::new(oid, params), signature).unwrap()
    }

    #[test]
    fn pss_defaults_absent_restrictions_and_decode_failures_are_distinct() {
        let default = pss(Some(&[0x30, 0]), true);
        assert_eq!(default.parameter_status, ParameterStatus::Decoded);
        let p = default.pss.unwrap();
        assert_eq!(p.hash_oid, "1.3.14.3.2.26");
        assert_eq!(p.mask_gen_hash_oid.as_deref(), Some("1.3.14.3.2.26"));
        assert_eq!(p.salt_length, 20);
        assert_eq!(pss(None, false).parameter_status, ParameterStatus::Absent);
        assert_eq!(
            pss(None, true).parameter_status,
            ParameterStatus::DecodeError
        );
        for bytes in [
            &[5, 0][..],
            &[0x30, 3, 0xa2, 1, 0],
            &[0x30, 6, 0xa2, 4, 2, 2, 1, 0], // Salt 256 exceeds pkcs1's representation.
            &[0x30, 2, 5, 0],                // Unconsumed inner data.
        ] {
            let info = pss(Some(bytes), true);
            assert_eq!(info.parameter_status, ParameterStatus::DecodeError);
            assert_eq!(info.parameters_der.as_deref(), Some(bytes));
            assert_eq!(info.pss, None);
        }
    }

    #[test]
    fn key_encoding_failures_do_not_become_unknown_algorithms_or_fake_sizes() {
        assert_eq!(
            key_details("1.3.101.112", None, &[0; 31], 0),
            (None, KeyDataStatus::DecodeError)
        );
        assert_eq!(
            key_details("1.3.101.113", None, &[0; 57], 1),
            (None, KeyDataStatus::DecodeError)
        );
        assert_eq!(
            key_details("1.2.3.4", None, &[0; 32], 0),
            (None, KeyDataStatus::Unparsed)
        );
        assert_eq!(
            key_details("1.2.840.10045.2.1", Some("1.2.3.4"), &[4; 65], 0),
            (None, KeyDataStatus::Unparsed)
        );
        assert_eq!(
            key_details(
                "1.2.840.10045.2.1",
                Some("1.2.840.10045.3.1.7"),
                &[4; 64],
                0
            ),
            (None, KeyDataStatus::DecodeError)
        );
        assert_eq!(
            key_details("1.2.840.113549.1.1.1", None, &[0x30, 0], 0),
            (None, KeyDataStatus::DecodeError)
        );
    }
}
