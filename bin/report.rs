use serde_json::{json, Value};
use x509_info::{CertificateInfo, GeneralName};

pub(crate) fn inspect(info: &CertificateInfo, summary: bool) -> crate::Result<Value> {
    let certificate = if summary {
        serde_json::to_value(info.summary())?
    } else {
        serde_json::to_value(info)?
    };
    let key = match info.public_key.details() {
        Ok(value) => json!({"fields":value,"diagnostic":null}),
        Err(error) => json!({"fields":null,"diagnostic":error}),
    };
    let mut name_diagnostics = Vec::new();
    for (which, name) in [("subject", &info.subject), ("issuer", &info.issuer)] {
        for (rdn_index, rdn) in name.rdns.iter().enumerate() {
            for (attribute_index, attribute) in rdn.iter().enumerate() {
                if let Some(diagnostic) = attribute.diagnostic() {
                    name_diagnostics.push(json!({
                        "name": which, "rdn_index": rdn_index,
                        "attribute_index": attribute_index, "diagnostic": diagnostic
                    }));
                }
            }
        }
    }
    let mut directory_attribute_values = Vec::new();
    let mut extension_diagnostics = Vec::new();
    let mut policy_qualifier_diagnostics = Vec::new();
    for (extension_index, extension) in info.extensions.iter().enumerate() {
        if let Some(diagnostic) = extension.diagnostic() {
            extension_diagnostics.push(json!({
                "index": extension_index, "oid": extension.oid, "diagnostic": diagnostic
            }));
        }
        match &extension.details {
            x509_info::ExtensionDetails::SubjectDirectoryAttributes(attributes) => {
                for (attribute_index, attribute) in attributes.iter().enumerate() {
                    let values: Vec<_> = attribute
                        .text_values()
                        .into_iter()
                        .map(|result| match result {
                            Ok(text) => json!({"text": text}),
                            Err(diagnostic) => json!({"diagnostic": diagnostic}),
                        })
                        .collect();
                    directory_attribute_values.push(json!({
                        "extension_index": extension_index,
                        "attribute_index": attribute_index, "values": values
                    }));
                }
            }
            x509_info::ExtensionDetails::CertificatePolicies(policies) => {
                for (policy_index, policy) in policies.iter().enumerate() {
                    for (qualifier_index, qualifier) in policy.qualifiers.iter().enumerate() {
                        if let Some(diagnostic) = qualifier.diagnostic() {
                            policy_qualifier_diagnostics.push(json!({
                                "extension_index": extension_index, "policy_index": policy_index,
                                "qualifier_index": qualifier_index, "diagnostic": diagnostic
                            }));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut value = json!({
        "report_version": 2,
        "certificate": certificate,
        "public_key_details": key,
        "spki_sha256_fingerprint_hex": hex::encode(info.public_key.spki_sha256_fingerprint()),
        "name_diagnostics": name_diagnostics,
        "directory_attribute_values": directory_attribute_values,
        "extension_diagnostics": extension_diagnostics,
        "policy_qualifier_diagnostics": policy_qualifier_diagnostics
    });
    enrich(&mut value)?;
    Ok(value)
}
// This is application DTO adaptation over the library's serialized owned model,
// not ASN.1 decoding. Enrichment adds fields and never replaces original values.
fn enrich(value: &mut Value) -> crate::Result<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                enrich(item)?;
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                enrich(item)?;
            }
            let name = match map.get("kind").and_then(Value::as_str) {
                Some("other_name") => map.get("value").and_then(|v| {
                    Some(GeneralName::OtherName {
                        oid: v.get("oid")?.as_str()?.into(),
                        name: v.get("name").and_then(Value::as_str).map(str::to_owned),
                        value_der_hex: v.get("value_der_hex")?.as_str()?.into(),
                    })
                }),
                Some("edi_party_name") => map.get("value").and_then(|v| {
                    Some(GeneralName::EdiPartyName {
                        constructed: v.get("constructed")?.as_bool()?,
                        content_hex: v.get("content_hex")?.as_str()?.into(),
                    })
                }),
                Some("x400_address") => map.get("value").and_then(|v| {
                    Some(GeneralName::X400Address {
                        constructed: v.get("constructed")?.as_bool()?,
                        content_hex: v.get("content_hex")?.as_str()?.into(),
                    })
                }),
                _ => None,
            };
            if let Some(name) = name {
                match name.details() {
                    Ok(details) => {
                        map.insert("decoded_fields".into(), serde_json::to_value(details)?);
                    }
                    Err(diagnostic) => {
                        map.insert(
                            "decode_diagnostic".into(),
                            serde_json::to_value(diagnostic)?,
                        );
                    }
                }
            }
        }
        _ => (),
    }
    Ok(())
}

pub(crate) fn toml_value(value: Value) -> crate::Result<toml::Value> {
    Ok(match value {
        Value::Null => return Err("TOML cannot represent a null array element".into()),
        Value::Bool(b) => toml::Value::Boolean(b),
        Value::String(s) => toml::Value::String(s),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if n.is_u64() {
                toml::Value::String(n.to_string())
            } else {
                toml::Value::Float(n.as_f64().ok_or("unrepresentable TOML number")?)
            }
        }
        Value::Array(a) => toml::Value::Array(
            a.into_iter()
                .map(toml_value)
                .collect::<crate::Result<_>>()?,
        ),
        Value::Object(m) => toml::Value::Table(
            m.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| Ok((k, toml_value(v)?)))
                .collect::<crate::Result<_>>()?,
        ),
    })
}
pub(crate) fn text(value: &Value) -> String {
    fn write(value: &Value, depth: usize, out: &mut String) {
        match value {
            Value::Object(m) => {
                for (k, v) in m {
                    out.push_str(&"  ".repeat(depth));
                    out.push_str(k);
                    out.push(':');
                    if v.is_object()
                        || v.as_array()
                            .is_some_and(|a| a.iter().any(|v| v.is_object() || v.is_array()))
                    {
                        out.push('\n');
                        write(v, depth + 1, out);
                    } else {
                        out.push(' ');
                        out.push_str(&v.to_string());
                        out.push('\n');
                    }
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    out.push_str(&format!("{}[{i}]\n", "  ".repeat(depth)));
                    write(v, depth + 1, out);
                }
            }
            v => out.push_str(&format!("{}{v}\n", "  ".repeat(depth))),
        }
    }
    let mut out = String::new();
    write(value, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_enriched_and_toml_rules_are_explicit() {
        let mut value = json!({"kind":"other_name","value":{"oid":"1.3.6.1.4.1.311.20.2.3","name":null,"value_der_hex":"a0030c0161"}});
        enrich(&mut value).unwrap();
        assert_eq!(value["decoded_fields"]["kind"], "user_principal_name");
        assert_eq!(value["decoded_fields"]["value"], "a");
        let value = toml_value(json!({"absent":null,"large":u64::MAX,"values":[1,2]})).unwrap();
        assert!(value.get("absent").is_none());
        assert_eq!(value["large"].as_str(), Some("18446744073709551615"));
        assert!(toml_value(json!([1, null, 2])).is_err());
    }
}
