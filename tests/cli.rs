#![cfg(feature = "cli")]

use base64ct::Encoding;

use std::{
    io::Write,
    process::{Command, Stdio},
};
const PEM: &[u8] = include_bytes!("fixtures/details.pem");
fn run(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut p = Command::new(env!("CARGO_BIN_EXE_x509-info"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Error/help paths may close stdin before reading it.
    let _ = p.stdin.take().unwrap().write_all(input);
    p.wait_with_output().unwrap()
}
fn success(args: &[&str], input: &[u8]) -> Vec<u8> {
    let o = run(args, input);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(o.stderr.is_empty());
    o.stdout
}
#[test]
fn report_formats_and_encoding_roundtrips_preserve_fields() {
    let json: serde_json::Value = serde_json::from_slice(&success(&["-f", "json"], PEM)).unwrap();
    assert_eq!(json["report_version"], 2);
    let info = x509_info::parse_pem(PEM, Default::default()).unwrap();
    assert_eq!(
        base64ct::Base64::decode_vec(json["certificate"]["der_base64"].as_str().unwrap()).unwrap(),
        info.der
    );
    assert!(json["certificate"].get("der").is_none());
    assert_eq!(
        json["certificate"]["serial_number_hex"],
        hex::encode(&info.serial_number)
    );
    assert_eq!(
        base64ct::Base64::decode_vec(
            json["certificate"]["signature_value_base64"]
                .as_str()
                .unwrap()
        )
        .unwrap(),
        info.signature_value
    );
    assert_eq!(
        json["public_key_details"]["fields"]["kind"],
        "ec_uncompressed"
    );
    assert_eq!(
        json["spki_sha256_fingerprint_hex"].as_str().unwrap().len(),
        64
    );
    let cbor = success(&["--format", "cbor"], PEM);
    let decoded: ciborium::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    fn field<'a>(value: &'a ciborium::Value, name: &str) -> &'a ciborium::Value {
        &value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .unwrap()
            .1
    }
    assert_eq!(
        field(field(&decoded, "certificate"), "der")
            .as_bytes()
            .unwrap(),
        &info.der
    );
    assert_eq!(
        field(&decoded, "report_version").as_integer().unwrap(),
        2.into()
    );
    let text = String::from_utf8(success(&[], PEM)).unwrap();
    assert!(text.contains("tbs_signature_algorithm:"));
    assert!(text.contains("x_hex:"));
    assert!(text.contains(&format!(
        "der_base64: {}",
        json["certificate"]["der_base64"]
    )));
    let full_toml: toml::Value =
        toml::from_str(&String::from_utf8(success(&["-f", "toml"], PEM)).unwrap()).unwrap();
    assert_eq!(
        full_toml["certificate"]["der_base64"].as_str(),
        json["certificate"]["der_base64"].as_str()
    );
    let toml: toml::Value =
        toml::from_str(&String::from_utf8(success(&["--summary", "-f", "toml"], PEM)).unwrap())
            .unwrap();
    assert!(toml["certificate"].get("der").is_none());
    assert_eq!(toml["report_version"].as_integer(), Some(2));
    let der = success(&["-f", "der"], PEM);
    let pem = success(&["--input-format", "der", "-f", "pem"], &der);
    assert_eq!(success(&["-f", "der"], &pem), der);
    let mut mismatch = der.clone();
    let oid = [6, 8, 42, 134, 72, 206, 61, 4, 3, 2];
    let offset = mismatch.windows(oid.len()).rposition(|w| w == oid).unwrap();
    mismatch[offset + oid.len() - 1] = 3;
    assert!(!success(&["-f", "json"], &mismatch).is_empty());
}
#[test]
fn qualifiers_and_private_field_decoding_are_in_reports() {
    let policies = include_bytes!("fixtures/policies.pem");
    let v: serde_json::Value = serde_json::from_slice(&success(&["-f", "json"], policies)).unwrap();
    let serialized = v.to_string();
    assert!(serialized.contains("user_notice"));
    assert!(serialized.contains("Example notice"));
    let rsa = include_bytes!("fixtures/rsa2048.pem");
    let v: serde_json::Value = serde_json::from_slice(&success(&["-f", "json"], rsa)).unwrap();
    assert_eq!(
        v["public_key_details"]["fields"]["value"]["exponent_hex"],
        "010001"
    );
}
#[test]
fn invalid_inputs_and_options_fail_without_stdout() {
    for (args, input) in [
        (vec!["--unknown"], PEM.to_vec()),
        (vec!["--max-input-bytes", "8"], PEM.to_vec()),
        (vec!["-f", "xml"], PEM.to_vec()),
        (vec!["--input-format", "der"], PEM.to_vec()),
        (vec!["--summary", "-f", "pem"], PEM.to_vec()),
        (vec![], [PEM, PEM].concat()),
        (vec![], vec![0xff]),
    ] {
        let output = run(&args, &input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    assert!(String::from_utf8(success(&["--help"], &[]))
        .unwrap()
        .contains("--input-format"));
}
#[test]
fn file_output_is_written_only_after_success() {
    let directory = std::env::temp_dir().join(format!("x509-info-cli-test-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let path = directory.join("certificate with spaces.pem");
    std::fs::write(&path, PEM).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_x509-info"))
        .arg(&path)
        .args(["-f", "der", "-o"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), success(&["-f", "der"], PEM));
    let before = std::fs::read(&path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_x509-info"))
        .arg(&path)
        .args(["--max-input-bytes", "1", "-o"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn clap_validates_arguments_and_documents_formats() {
    for args in [
        vec!["--format", "xml"],
        vec!["--format"],
        vec!["--input-format", "unknown"],
        vec!["--max-input-bytes", "0"],
        vec!["--max-input-bytes", "-1"],
        vec!["--summary", "--format", "der"],
        vec!["first.pem", "second.pem"],
    ] {
        let output = run(&args, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }
    let help = String::from_utf8(success(&["--help"], &[])).unwrap();
    for format in [
        "text",
        "json",
        "jsonl",
        "yaml",
        "messagepack",
        "cbor",
        "toml",
        "der",
        "pem",
    ] {
        assert!(help.contains(format));
    }
    assert!(String::from_utf8(success(&["--version"], &[]))
        .unwrap()
        .contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        success(&["--format=der", "-"], PEM),
        success(&["-f", "der"], PEM)
    );
}

#[test]
fn fido_uuid_and_unusual_lengths_survive_all_reports() {
    use x509_cert::der::{
        asn1::{ObjectIdentifier, OctetString},
        Any, Decode, Encode, Tag, TagNumber,
    };
    let info = x509_info::parse_pem(PEM, Default::default()).unwrap();
    let mut certificate = Vec::<Any>::from_der(&info.der).unwrap();
    let mut tbs = Vec::<Any>::from_der(&certificate[0].to_der().unwrap()).unwrap();
    let inputs = [
        hex::decode("08987058cadc4b81b6e130de50dcbe96").unwrap(),
        vec![0, 255],
    ];
    let extensions: Vec<_> = inputs
        .iter()
        .map(|bytes| x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new("1.3.6.1.4.1.45724.1.1.4").unwrap(),
            critical: false,
            extn_value: OctetString::new(
                OctetString::new(bytes.clone()).unwrap().to_der().unwrap(),
            )
            .unwrap(),
        })
        .collect();
    tbs.pop().unwrap();
    tbs.push(
        Any::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(3),
            },
            extensions.to_der().unwrap(),
        )
        .unwrap(),
    );
    certificate[0] = Any::from_der(&tbs.to_der().unwrap()).unwrap();
    // Retain the old signature: reports parse assertions without verifying them.
    let der = certificate.to_der().unwrap();
    for summary in [false, true] {
        let mut args = vec!["-f", "json"];
        if summary {
            args.push("--summary");
        }
        let value: serde_json::Value = serde_json::from_slice(&success(&args, &der)).unwrap();
        let ext = &value["certificate"]["extensions"];
        assert_eq!(
            ext[0]["details"]["value"]["uuid"],
            "08987058-cadc-4b81-b6e1-30de50dcbe96"
        );
        assert_eq!(ext[1]["details"]["value"]["raw_base64"], "AP8=");
        assert_eq!(
            ext[1]["details"]["value"]["format_diagnostic"]["issue"],
            "invalid_length"
        );
    }
    for format in ["text", "toml"] {
        let output = String::from_utf8(success(&["-f", format], &der)).unwrap();
        assert!(output.contains("08987058-cadc-4b81-b6e1-30de50dcbe96"));
        assert!(output.contains("AP8="));
        assert!(output.contains("invalid_length"));
    }
    assert_eq!(success(&["-f", "der"], &der), der);
}

#[test]
fn json_lines_and_messagepack_preserve_the_report_model() {
    let json: serde_json::Value = serde_json::from_slice(&success(&["-f", "json"], PEM)).unwrap();
    let line = success(&["-f", "jsonl"], PEM);
    assert_eq!(line.iter().filter(|&&c| c == b'\n').count(), 1);
    assert_eq!(line.last(), Some(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&line).unwrap(),
        json
    );
    let cbor: ciborium::Value =
        ciborium::from_reader(success(&["-f", "cbor"], PEM).as_slice()).unwrap();
    let packed = success(&["-f", "messagepack"], PEM);
    let messagepack: ciborium::Value = rmp_serde::from_slice(&packed).unwrap();
    assert_eq!(messagepack, cbor);
    assert_eq!(success(&["-f", "msgpack"], PEM), packed);
    let yaml = String::from_utf8(success(&["-f", "yaml"], PEM)).unwrap();
    assert!(yaml.contains("der_base64:"));
    assert!(yaml.contains("report_version: 2"));
}

#[test]
fn schemas_are_generated_without_certificate_input() {
    for args in [vec!["--schema"], vec!["--schema", "--summary"]] {
        let schema: serde_json::Value = serde_json::from_slice(&success(&args, &[])).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["properties"]["report_version"]["const"], 2);
        assert!(schema["$defs"].as_object().unwrap().len() > 20);
    }
    for args in [
        vec!["--schema", "certificate.pem"],
        vec!["--schema", "--format", "der"],
        vec!["--schema", "--input-format", "pem"],
        vec!["--schema", "--max-input-bytes", "10"],
    ] {
        assert_eq!(run(&args, &[]).status.code(), Some(2));
    }
}
