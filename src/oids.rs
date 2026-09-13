use oid_registry::{Oid, OidRegistry};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

/// A name lookup received an invalid or noncanonical dotted-decimal OID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("expected a canonical dotted-decimal object identifier")]
pub struct InvalidOid;

/// Caller-owned OID presentation names, independent of parsing or trust policy.
///
/// Default uses the upstream oid-registry crypto/X.500/X.509 tables plus
/// application labels and newer standard OIDs without copying the base names.
/// Clones share an immutable base registry; caller overrides remain independent. No mutable global
/// registry is used. Names can change across crate/database releases; use OIDs
/// for program logic. Adding a name never enables a decoder or cryptographic operation.
/// Pass this table to parse_der_with_names/parse_pem_with_names to customize output.
///
/// ```
/// let mut names = x509_info::OidNames::default();
/// names.insert("1.2.3.4", "Internal certificate purpose")?;
/// assert_eq!(names.get("1.2.3.4"), Some("Internal certificate purpose"));
/// # Ok::<(), x509_info::InvalidOid>(())
/// ```
#[derive(Clone, Debug)]
pub struct OidNames {
    registry: Arc<OidRegistry<'static>>,
    overrides: BTreeMap<String, String>,
}

impl Default for OidNames {
    fn default() -> Self {
        let registry = OidRegistry::default().with_crypto().with_x509().with_x500();
        Self {
            registry: Arc::new(registry),
            overrides: BTreeMap::new(),
        }
    }
}

impl OidNames {
    /// Look up an exact canonical dotted-decimal OID. Unknown/invalid input returns None.
    /// The borrowed label lives as long as this table; parsed results copy it.
    pub fn get(&self, oid: &str) -> Option<&str> {
        let parsed = canonical_oid(oid).ok()?;
        self.overrides
            .get(oid)
            .map(String::as_str)
            .or_else(|| {
                LABELS
                    .iter()
                    .find(|(id, _)| *id == oid)
                    .map(|(_, name)| *name)
            })
            .or_else(|| self.registry.get(&parsed).map(|entry| entry.sn()))
    }

    /// Add/override a label, returning the previous owned label if present.
    ///
    /// # Errors
    /// Returns InvalidOid for invalid or noncanonical dotted-decimal syntax.
    /// Labels are application-controlled presentation text, not sanitized markup.
    pub fn insert(
        &mut self,
        oid: &str,
        name: impl Into<String>,
    ) -> Result<Option<String>, InvalidOid> {
        canonical_oid(oid)?;
        let previous = self.get(oid).map(str::to_owned);
        self.overrides.insert(oid.into(), name.into());
        Ok(previous)
    }
}

fn canonical_oid(oid: &str) -> Result<Oid<'static>, InvalidOid> {
    let mut arcs = oid.split('.');
    let first = arcs.next().ok_or(InvalidOid)?;
    let second: u64 = arcs
        .next()
        .ok_or(InvalidOid)?
        .parse()
        .map_err(|_| InvalidOid)?;
    if !matches!(first, "0" | "1" | "2") || (first != "2" && second >= 40) {
        return Err(InvalidOid);
    }
    let parsed = Oid::from_str(oid).map_err(|_| InvalidOid)?;
    if parsed.to_id_string() != oid {
        return Err(InvalidOid);
    }
    Ok(parsed)
}

// Keep existing application labels stable. The upstream database supplies the
// broader vocabulary; additions here cover common standards absent from that snapshot.
const LABELS: &[(&str, &str)] = &[
    ("2.5.4.3", "CN"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.5", "serialNumber"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("1.2.840.113549.1.9.1", "emailAddress"),
    ("1.2.840.113549.1.1.1", "RSA"),
    ("1.2.840.113549.1.1.10", "RSA-PSS"),
    ("1.2.840.10045.2.1", "EC"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
    ("1.3.101.110", "X25519"),
    ("1.3.101.111", "X448"),
    ("1.2.840.113549.1.1.5", "RSA-SHA1"),
    ("1.2.840.113549.1.1.14", "RSA-SHA224"),
    ("1.2.840.113549.1.1.11", "RSA-SHA256"),
    ("1.2.840.113549.1.1.12", "RSA-SHA384"),
    ("1.2.840.113549.1.1.13", "RSA-SHA512"),
    ("1.2.840.10045.4.1", "ECDSA-SHA1"),
    ("1.2.840.10045.4.3.1", "ECDSA-SHA224"),
    ("1.2.840.10045.4.3.2", "ECDSA-SHA256"),
    ("1.2.840.10045.4.3.3", "ECDSA-SHA384"),
    ("1.2.840.10045.4.3.4", "ECDSA-SHA512"),
    ("2.16.840.1.101.3.4.3.9", "ECDSA-SHA3-224"),
    ("2.16.840.1.101.3.4.3.10", "ECDSA-SHA3-256"),
    ("2.16.840.1.101.3.4.3.11", "ECDSA-SHA3-384"),
    ("2.16.840.1.101.3.4.3.12", "ECDSA-SHA3-512"),
    ("2.16.840.1.101.3.4.3.13", "RSA-SHA3-224"),
    ("2.16.840.1.101.3.4.3.14", "RSA-SHA3-256"),
    ("2.16.840.1.101.3.4.3.15", "RSA-SHA3-384"),
    ("2.16.840.1.101.3.4.3.16", "RSA-SHA3-512"),
    ("2.16.840.1.101.3.4.2.7", "SHA3-224"),
    ("2.16.840.1.101.3.4.2.8", "SHA3-256"),
    ("2.16.840.1.101.3.4.2.9", "SHA3-384"),
    ("2.16.840.1.101.3.4.2.10", "SHA3-512"),
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
    ("1.2.840.10045.3.1.1", "P-192"),
    ("1.3.132.0.33", "P-224"),
    ("1.2.840.10045.3.1.7", "P-256"),
    ("1.3.132.0.34", "P-384"),
    ("1.3.132.0.35", "P-521"),
    ("1.3.132.0.10", "secp256k1"),
    ("1.2.156.10197.1.301", "SM2"),
    ("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"),
    ("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"),
    ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),
    ("2.5.29.37.0", "any_extended_key_usage"),
    ("1.3.6.1.5.5.7.3.1", "server_auth"),
    ("1.3.6.1.5.5.7.3.2", "client_auth"),
    ("1.3.6.1.5.5.7.3.3", "code_signing"),
    ("1.3.6.1.5.5.7.3.4", "email_protection"),
    ("1.3.6.1.5.5.7.3.8", "time_stamping"),
    ("1.3.6.1.5.5.7.3.9", "ocsp_signing"),
    ("1.3.6.1.5.5.7.3.5", "ipsec_end_system"),
    ("1.3.6.1.5.5.7.3.6", "ipsec_tunnel"),
    ("1.3.6.1.5.5.7.3.7", "ipsec_user"),
    ("1.3.6.1.5.5.7.3.17", "ipsec_ike"),
    ("1.3.6.1.4.1.311.20.2.2", "smart_card_logon"),
    ("1.3.6.1.5.5.7.48.1", "ocsp"),
    ("1.3.6.1.5.5.7.48.2", "ca_issuers"),
    ("1.3.6.1.5.5.7.48.5", "ca_repository"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_coverage_and_application_labels_are_preserved() {
        let names = OidNames::default();
        let registry = OidRegistry::default().with_crypto().with_x509().with_x500();
        for (oid, entry) in registry.iter() {
            let id = oid.to_id_string();
            let expected = LABELS
                .iter()
                .find(|(key, _)| *key == id)
                .map_or(entry.sn(), |(_, label)| *label);
            assert_eq!(names.get(&id), Some(expected), "{id}");
        }
        for (oid, label) in LABELS {
            assert_eq!(names.get(oid), Some(*label));
        }
    }

    #[test]
    fn overrides_return_previous_values_and_clones_are_independent() {
        let mut names = OidNames::default();
        // Exercise both an upstream-only name and an application alias.
        let upstream = names
            .registry
            .keys()
            .map(Oid::to_id_string)
            .find(|id| !LABELS.iter().any(|(key, _)| key == id))
            .unwrap();
        for oid in [upstream.as_str(), "2.5.4.3", "1.2.3.4"] {
            let previous = names.get(oid).map(str::to_owned);
            assert_eq!(names.insert(oid, "first").unwrap(), previous);
            let mut cloned = names.clone();
            assert_eq!(
                cloned.insert(oid, "second").unwrap().as_deref(),
                Some("first")
            );
            assert_eq!(names.get(oid), Some("first"));
            assert_eq!(cloned.get(oid), Some("second"));
        }
        for invalid in ["2.05.4.3", " 2.5.4.3", "3.1", "1.40", "1.2.", ""] {
            assert_eq!(names.get(invalid), None);
            assert!(names.insert(invalid, "invalid").is_err());
        }
        assert_eq!(OidNames::default().get("1.2.3.4"), None);
    }
}
