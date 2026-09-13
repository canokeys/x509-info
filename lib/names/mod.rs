pub(crate) mod details;

use crate::OidNames;
use x509_parser::x509::{AttributeTypeAndValue, X509Name};

/// One attribute in a relative distinguished name; no normalization or name matching.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct NameAttribute {
    /// Dotted-decimal attribute OID, including unknown attributes.
    pub oid: String,
    /// Common attribute label, when recognized (for example CN or O).
    pub label: Option<String>,
    /// Decoded UTF-8/Printable/Numeric/IA5/Visible/BMP/Universal text, or None.
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

pub(crate) fn inspect_attribute(
    attr: &AttributeTypeAndValue<'_>,
    names: &OidNames,
) -> NameAttribute {
    let oid = attr.attr_type().to_id_string();
    NameAttribute {
        label: names.get(&oid).map(str::to_owned),
        oid,
        value: crate::decoding::text(attr.attr_value()).ok(),
        value_tag: attr.attr_value().tag().0,
        value_hex: hex::encode(attr.as_slice()),
    }
}

pub(crate) fn inspect_name(name: &X509Name<'_>, names: &OidNames) -> DistinguishedName {
    DistinguishedName {
        display: name.to_string(),
        der: name.as_raw().to_vec(),
        rdns: name
            .iter_rdn()
            .map(|rdn| rdn.iter().map(|a| inspect_attribute(a, names)).collect())
            .collect(),
    }
}

impl NameAttribute {
    /// Explain missing text by re-decoding the retained tag/content. No name policy runs.
    /// Returns None when text is decodable, including for a mutated public field.
    pub fn diagnostic(&self) -> Option<crate::DecodeDiagnostic> {
        let bytes = match hex::decode(&self.value_hex) {
            Ok(b) => b,
            Err(_) => return Some(crate::DecodeDiagnostic::invalid("name value hex")),
        };
        let any = x509_parser::asn1_rs::Any::from_tag_and_data(
            x509_parser::asn1_rs::Tag(self.value_tag),
            &bytes,
        );
        crate::decoding::text(&any).err()
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
        let owned = inspect_name(&name, &OidNames::default());
        assert_eq!(owned.der, bytes);
        let attr = &owned.rdns[0][0];
        assert_eq!(attr.value, None);
        assert_eq!(attr.value_tag, 2);
        assert_eq!(attr.value_hex, "2a");
    }
}
