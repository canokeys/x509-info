// Report-only byte and identifier formatting. Library Serde contracts stay intact.
use base64ct::{Base64, Encoding};
use ciborium::Value as Binary;
use serde_json::{json, Value};

// Convert known byte fields explicitly; numeric lists (TLS features, notice
// numbers, transport bits) must never be guessed to be byte arrays.
pub(crate) fn binary(value: Value) -> crate::Result<Binary> {
    Ok(match value {
        Value::Array(values) => Binary::Array(
            values
                .into_iter()
                .map(binary)
                .collect::<crate::Result<_>>()?,
        ),
        Value::Object(mut fields) => {
            let kind = fields
                .get("kind")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if kind.as_deref() == Some("fido_aaguid") {
                let bytes = hex_bytes(fields.remove("value").ok_or("missing AAGUID")?)?;
                let formatted = match uuid::Uuid::from_slice(&bytes) {
                    Ok(id) => json!({"uuid": id.hyphenated().to_string()}),
                    Err(_) => json!({
                        "uuid": null,
                        "raw_hex": hex::encode(bytes),
                        "format_diagnostic": {
                            "issue": "invalid_length",
                            "field": "AAGUID",
                            "expected_bytes": 16
                        }
                    }),
                };
                fields.insert("value".into(), formatted);
            }
            let opaque_content = fields.contains_key("constructed");
            let mut output = Vec::new();
            for (key, value) in fields {
                let (key, value) = match key.as_str() {
                    "der" | "spki_der" | "parameters_der" | "key_bytes" | "signature_value"
                    | "value_der" => {
                        let bytes = if value.is_null() {
                            Binary::Null
                        } else {
                            Binary::Bytes(serde_json::from_value::<Vec<u8>>(value)?)
                        };
                        (key, bytes)
                    }
                    "serial_number" => (
                        "serial_number_hex".into(),
                        Binary::Text(hex::encode(serde_json::from_value::<Vec<u8>>(value)?)),
                    ),
                    "value_der_hex" | "encoded_hex" | "extensions_hex" | "signature_hex"
                    | "raw_hex" => (
                        key.trim_end_matches("_hex").into(),
                        Binary::Bytes(hex_bytes(value)?),
                    ),
                    "values_der_hex" => (
                        "values_der".into(),
                        Binary::Array(
                            value
                                .as_array()
                                .ok_or("invalid DER values")?
                                .iter()
                                .cloned()
                                .map(|value| Ok(Binary::Bytes(hex_bytes(value)?)))
                                .collect::<crate::Result<_>>()?,
                        ),
                    ),
                    "value_hex" => ("value_raw".into(), Binary::Bytes(hex_bytes(value)?)),
                    "content_hex" if opaque_content => {
                        ("content".into(), Binary::Bytes(hex_bytes(value)?))
                    }
                    "value"
                        if matches!(
                            kind.as_deref(),
                            Some(
                                "subject_key_identifier"
                                    | "malformed_ip"
                                    | "edwards"
                                    | "montgomery"
                            )
                        ) =>
                    {
                        ("value_hex".into(), binary(value)?)
                    }
                    _ => (key, binary(value)?),
                };
                output.push((Binary::Text(key), value));
            }
            Binary::Map(output)
        }
        other => Binary::serialized(&other)?,
    })
}

fn hex_bytes(value: Value) -> crate::Result<Vec<u8>> {
    Ok(hex::decode(value.as_str().ok_or("invalid hex field")?)?)
}

// Textual formats share this projection. CBOR is emitted from the binary tree,
// so it never passes through Base64 strings or loses native byte-string types.
pub(crate) fn textual(value: Binary) -> crate::Result<Value> {
    Ok(match value {
        Binary::Bytes(bytes) => Value::String(Base64::encode_string(&bytes)),
        Binary::Array(values) => Value::Array(
            values
                .into_iter()
                .map(textual)
                .collect::<crate::Result<_>>()?,
        ),
        Binary::Map(fields) => {
            let mut output = serde_json::Map::new();
            for (key, value) in fields {
                let Binary::Text(mut key) = key else {
                    return Err("report map keys must be text".into());
                };
                if matches!(value, Binary::Bytes(_))
                    || key == "values_der"
                    || (key == "parameters_der" && matches!(value, Binary::Null))
                {
                    key.push_str("_base64");
                }
                output.insert(key, textual(value)?);
            }
            Value::Object(output)
        }
        other => other.deserialized()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_bytes_roundtrip_without_converting_numeric_lists() {
        let input = json!({
            "der": [0, 255, 1, 128],
            "parameters_der": null,
            "signature_hex": "00ff",
            "values_der_hex": ["", "0500"],
            "name": {"value": "Alice", "value_hex": "416c696365"},
            "opaque": {"constructed": true, "content_hex": "00ff"},
            "integer": {"content_hex": "ff", "value": -1},
            "tls_features": [5, 17],
            "unknown_bits": [],
            "modulus_hex": "00ff",
            "serial_number": [0, 128]
        });
        let native = binary(input).unwrap();
        let text = textual(native.clone()).unwrap();
        assert_eq!(text["der_base64"], "AP8BgA==");
        assert!(text["parameters_der_base64"].is_null());
        assert_eq!(text["signature_base64"], "AP8=");
        assert_eq!(text["values_der_base64"], json!(["", "BQA="]));
        assert_eq!(text["name"]["value"], "Alice");
        assert_eq!(text["name"]["value_raw_base64"], "QWxpY2U=");
        assert_eq!(text["opaque"]["content_base64"], "AP8=");
        assert_eq!(text["integer"], json!({"content_hex": "ff", "value": -1}));
        assert_eq!(text["tls_features"], json!([5, 17]));
        assert_eq!(text["unknown_bits"], json!([]));
        assert_eq!(text["modulus_hex"], "00ff");
        assert_eq!(text["serial_number_hex"], "0080");
        let mut bytes = Vec::new();
        ciborium::into_writer(&native, &mut bytes).unwrap();
        let decoded: Binary = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, native);
        assert_eq!(textual(decoded).unwrap(), text);
    }

    #[test]
    fn aaguid_formats_bytes_without_uuid_policy_or_endian_swaps() {
        for (hex, expected) in [
            (
                "08987058cadc4b81b6e130de50dcbe96",
                "08987058-cadc-4b81-b6e1-30de50dcbe96",
            ),
            (
                "00000000000000000000000000000000",
                "00000000-0000-0000-0000-000000000000",
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
        ] {
            let output =
                textual(binary(json!({"kind":"fido_aaguid","value":hex})).unwrap()).unwrap();
            assert_eq!(output["value"], json!({"uuid": expected}));
        }
        for bytes in [vec![], vec![0, 255], vec![255; 17]] {
            let output =
                textual(binary(json!({"kind":"fido_aaguid","value":hex::encode(&bytes)})).unwrap())
                    .unwrap();
            assert!(output["value"]["uuid"].is_null());
            assert_eq!(
                output["value"]["format_diagnostic"]["issue"],
                "invalid_length"
            );
            assert_eq!(
                Base64::decode_vec(output["value"]["raw_base64"].as_str().unwrap()).unwrap(),
                bytes
            );
        }
    }
}
