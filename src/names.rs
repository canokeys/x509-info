use x509_parser::x509::X509Name;

/// One attribute in a relative distinguished name; no normalization or name matching.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct NameAttribute {
    /// Dotted-decimal attribute OID, including unknown attributes.
    pub oid: String,
    /// Common attribute label, when recognized (for example CN or O).
    pub label: Option<String>,
    /// Decoded UTF-8/Printable/Numeric/IA5 text, or None for other/invalid encodings.
    /// No lossy decoding is used. Raw value content remains available in value_hex.
    pub value: Option<String>,
    /// ASN.1 tag number of the value; the complete Name DER preserves its header.
    pub value_tag: u32,
    /// Lowercase hexadecimal ASN.1 value content, without tag/length bytes.
    pub value_hex: String,
}

/// Owned distinguished name, retaining RDN grouping, repeated attributes and order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DistinguishedName {
    /// Parser-generated display text; do not use string equality as name matching.
    pub display: String,
    /// RDNs in encoded order, each containing its attributes in encoded order.
    pub rdns: Vec<Vec<NameAttribute>>,
    /// Complete DER Name encoding, preserving string types and exact bytes.
    pub der: Vec<u8>,
}

pub(crate) fn inspect_name(name: &X509Name<'_>) -> DistinguishedName {
    DistinguishedName {
        display: name.to_string(),
        der: name.as_raw().to_vec(),
        rdns: name
            .iter_rdn()
            .map(|rdn| {
                rdn.iter()
                    .map(|attr| {
                        let oid = attr.attr_type().to_id_string();
                        let label = match oid.as_str() {
                            "2.5.4.3" => Some("CN"),
                            "2.5.4.6" => Some("C"),
                            "2.5.4.7" => Some("L"),
                            "2.5.4.8" => Some("ST"),
                            "2.5.4.10" => Some("O"),
                            "2.5.4.11" => Some("OU"),
                            "2.5.4.5" => Some("serialNumber"),
                            "0.9.2342.19200300.100.1.25" => Some("DC"),
                            "1.2.840.113549.1.9.1" => Some("emailAddress"),
                            _ => None,
                        }
                        .map(str::to_owned);
                        NameAttribute {
                            oid,
                            label,
                            value: attr.as_str().ok().map(str::to_owned),
                            value_tag: attr.attr_value().tag().0,
                            value_hex: hex::encode(attr.as_slice()),
                        }
                    })
                    .collect()
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    #[test]
    fn unsupported_name_value_encodings_are_retained_without_lossy_text() {
        // Name -> RDN -> CN attribute -> INTEGER, deliberately not a DirectoryString.
        let bytes = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 85, 4, 3, 2, 1, 42];
        let (_, name) = X509Name::from_der(&bytes).unwrap();
        let owned = inspect_name(&name);
        assert_eq!(owned.der, bytes);
        let attr = &owned.rdns[0][0];
        assert_eq!(attr.value, None);
        assert_eq!(attr.value_tag, 2);
        assert_eq!(attr.value_hex, "2a");
    }
}
