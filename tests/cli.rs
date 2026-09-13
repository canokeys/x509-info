#![cfg(feature = "cli")]

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
    assert_eq!(json["report_version"], 1);
    assert!(json["certificate"]["der"].is_array());
    assert_eq!(
        json["public_key_details"]["fields"]["kind"],
        "ec_uncompressed"
    );
    assert_eq!(
        json["spki_sha256_fingerprint_hex"].as_str().unwrap().len(),
        64
    );
    let cbor = success(&["--format", "cbor"], PEM);
    let decoded: serde_json::Value = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert_eq!(decoded, json);
    let text = String::from_utf8(success(&[], PEM)).unwrap();
    assert!(text.contains("tbs_signature_algorithm:"));
    assert!(text.contains("x_hex:"));
    let toml: toml::Value =
        toml::from_str(&String::from_utf8(success(&["--summary", "-f", "toml"], PEM)).unwrap())
            .unwrap();
    assert!(toml["certificate"].get("der").is_none());
    assert_eq!(toml["report_version"].as_integer(), Some(1));
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
    assert!(help.contains("text, json, cbor, toml, der, pem"));
    assert!(String::from_utf8(success(&["--version"], &[]))
        .unwrap()
        .contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        success(&["--format=der", "-"], PEM),
        success(&["-f", "der"], PEM)
    );
}
