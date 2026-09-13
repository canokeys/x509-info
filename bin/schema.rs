// Generate from Rust serialization types, then apply the CLI presentation rules.
// No schema is inferred from sample certificates.
use schemars::generate::{Contract, SchemaSettings};
use serde_json::{json, Value};

use crate::{
    encoding::{field_rule, Aaguid, FieldFormat},
    report::{Report, VERSION},
};

pub(crate) fn generate(summary: bool) -> crate::Result<Value> {
    let mut generator = SchemaSettings::draft2020_12()
        .with(|settings| settings.contract = Contract::Serialize)
        .into_generator();
    // Register helper types which enrich the library's GeneralName projection.
    let name = serde_json::to_value(generator.subschema_for::<Option<x509_info::NameDetails>>())?;
    let diagnostic =
        serde_json::to_value(generator.subschema_for::<x509_info::DecodeDiagnostic>())?;
    let aaguid = serde_json::to_value(generator.subschema_for::<Aaguid>())?;
    let schema = if summary {
        generator.into_root_schema_for::<Report<x509_info::CertificateSummary>>()
    } else {
        generator.into_root_schema_for::<Report<x509_info::CertificateInfo>>()
    };
    let mut schema = serde_json::to_value(schema)?;
    adapt(&mut schema, &name, &diagnostic, &aaguid);
    let mode = if summary { "summary" } else { "full" };
    schema["$id"] = json!(format!("urn:x509-info:report:{VERSION}:{mode}"));
    schema["title"] = json!(format!("x509-info report v{VERSION} ({mode})"));
    schema["description"] = json!("Textual report data model for JSON, JSON Lines and YAML. Describes parsed assertions and encodings, not certificate validity. TOML and binary format differences are documented in bin/README.md.");
    schema["properties"]["report_version"] = json!({"type":"integer", "const": VERSION});
    Ok(schema)
}

fn base64(nullable: bool) -> Value {
    let mut schema = json!({
        "type":"string",
        "contentEncoding":"base64",
        "pattern":"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
        "description":"Original octets as standard padded Base64, without line breaks."
    });
    if nullable {
        schema["type"] = json!(["string", "null"]);
    }
    schema
}

fn hex() -> Value {
    json!({"type":"string", "pattern":"^(?:[0-9a-f]{2})*$", "description":"Octets in lowercase, unseparated hex."})
}

fn adapt(schema: &mut Value, name: &Value, diagnostic: &Value, aaguid: &Value) {
    match schema {
        Value::Array(items) => {
            for item in items {
                adapt(item, name, diagnostic, aaguid);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                adapt(item, name, diagnostic, aaguid);
            }
            let Some(properties) = map.get_mut("properties").and_then(Value::as_object_mut) else {
                return;
            };
            let kind = properties
                .get("kind")
                .and_then(|v| v.get("const").or_else(|| v.get("enum")?.get(0)))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let opaque = properties.contains_key("constructed");
            let mut renames = Vec::new();
            for key in properties.keys().cloned().collect::<Vec<_>>() {
                if let Some((mut renamed, format)) = field_rule(&key, kind.as_deref(), opaque) {
                    let value = match format {
                        FieldFormat::Octets => {
                            renamed.push_str("_base64");
                            base64(key == "parameters_der")
                        }
                        FieldFormat::Hex => {
                            renamed.push_str("_base64");
                            base64(false)
                        }
                        FieldFormat::HexList => {
                            renamed.push_str("_base64");
                            json!({"type":"array", "items":base64(false)})
                        }
                        FieldFormat::Serial | FieldFormat::NamedHex => hex(),
                    };
                    properties.remove(&key);
                    properties.insert(renamed.clone(), value);
                    renames.push((key, renamed));
                }
            }
            if kind.as_deref() == Some("fido_aaguid") {
                properties.insert("value".into(), aaguid.clone());
            }
            if let Some(uuid) = properties.get_mut("uuid") {
                if uuid.get("type").and_then(Value::as_str) == Some("string") {
                    // UUID formatting only: all-zero and nonstandard versions/variants are valid report strings.
                    uuid["pattern"] =
                        json!("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
                }
            }
            let enriched = matches!(
                kind.as_deref(),
                Some("other_name" | "edi_party_name" | "x400_address")
            );
            if enriched {
                properties.insert("decoded_fields".into(), name.clone());
                properties.insert("decode_diagnostic".into(), diagnostic.clone());
            }
            if let Some(required) = map.get_mut("required").and_then(Value::as_array_mut) {
                for key in required {
                    if let Some((_, new)) = renames
                        .iter()
                        .find(|(old, _)| key.as_str() == Some(old.as_str()))
                    {
                        *key = json!(new);
                    }
                }
            }
            if kind.as_deref() == Some("fido_aaguid") {
                map.insert("description".into(), json!("FIDO AAGUID as a UUID string, or original bytes with a length diagnostic. No UUID version, variant or device policy is enforced."));
            }
            if enriched {
                map.insert(
                    "oneOf".into(),
                    json!([
                        {"required":["decoded_fields"]},
                        {"required":["decode_diagnostic"]}
                    ]),
                );
            }
        }
        _ => {}
    }
}
