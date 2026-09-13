# x509-info

Owned X.509 certificate information for applications, independent of CanoKey,
transport, bindings and runtime state. Callers own inputs and results. This crate
turns established parsers' types into certificate details that UI and reporting
code can use without importing ASN.1 types or maintaining OID conversion tables.

## Use

The experimental package is not yet published. From another local workspace:

```toml
[dependencies]
x509-info = { path = "path/to/libcanokey/crates/x509-info", features = ["serde"] }
serde_json = "1"
```

```rust
use x509_info::{parse_der, ParseOptions};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let der = std::fs::read("certificate.der")?; // Application-owned file I/O.
    let info = parse_der(&der, ParseOptions::default())?;
    let details = info.summary();
    drop(info); // The summary owns all its data.
    println!("{}", details.subject.display);
    println!("{}", serde_json::to_string_pretty(&details)?);
    Ok(())
}
```

Without `serde`, the same owned Rust API works for UI and binding adapters. The
optional `canokey::x509` facade re-exports this crate; no CanoKey crate is a dependency.

## Implemented information

- Subject/issuer text and ordered RDN groups, including repeated and unknown attributes.
- Version, original serial bytes, explicit validity timestamps and SHA-256 fingerprint.
- Algorithm OIDs and common labels; RSA sizes, selected named EC curves, Ed25519/Ed448,
  RSA-PSS parameters/defaults and separate parameter/key-encoding status.
- SAN (DNS, email, IP, URI, directory name and registered ID), KU, EKU and Basic Constraints.
- Raw certificate/name/SPKI/signature/extension data, unknown OIDs and duplicate extension flags.

Unsupported extensions stay `Unsupported`; failed supported extension decoding stays
`Malformed`. Every duplicate OID occurrence is marked, with no first/last-wins policy.
Invalid SAN entries remain visible individually. A malformed supported key encoding
is distinct from an unrecognized algorithm/curve. These findings are not trust decisions.

The parser accepts exactly one bounded DER/PEM certificate (default 1 MiB encoded
input), rejects trailing objects and mismatched inner/outer signature identifiers.
The input budget is not an exact peak-memory bound: full results and summaries own
copies. Parsing does not verify signatures, chains, identities, revocation, critical
extension policy or mathematical key validity. `validity.contains(timestamp)` only
checks the encoded interval; no clock, network, randomness or filesystem is accessed.

## Summary contract

`info.summary()` returns `CertificateSummary`, whose optional Serde representation
has `schema_version: 1`. It omits full DER, raw key/signature/parameter/extension bytes.
Keep `CertificateInfo` when the application needs those encodings. Full-result Serde
is also available, but is a diagnostic representation tied to crate SemVer, not the
versioned summary contract.

- Byte values in the summary use lowercase unseparated hex. Serial hex preserves
  the original INTEGER content, including sign padding. Name attribute value hex
  preserves unsupported string encodings without lossy conversion.
- Times are signed Unix seconds. OIDs use dotted decimal. Missing/unknown optional
  values serialize as null. RDNs are arrays of attribute arrays, not flattened maps.
- Enums use snake_case `kind`/`value` tags; status enums use snake_case strings.
  Consumers must tolerate additional fields and unknown kinds/statuses. Incompatible
  representation changes require a new schema major. JSON object order is not a contract.
- Names/labels are presentation conveniences; do not compare identities by display
  strings. UTF8/Printable/Numeric/IA5 values are decoded; other string encodings retain
  raw content with `value: null`. No Unicode or DN normalization is performed.

Public-key sizes are modulus/nominal curve sizes, never security-strength estimates.
Ed25519 reports 255 while its encoding has 256 bits; Ed448 reports 448 versus 456
encoded bits. EC inspection checks supported SEC1 lengths, not curve equations.
RSA-PSS uses RustCrypto `pkcs1`: its current representation supports salt lengths
up to 255 and trailer field 1. Other encodings produce `DecodeError` with raw
parameters retained; that status does not by itself prove an invalid certificate.
Explicit EC parameters and unrecognized algorithm parameters remain unparsed.

## Executable examples

Run from the repository root:

```sh
cargo run -p x509-info --example details --locked
cargo run -p x509-info --features serde --example export_json --locked
cargo run -p x509-info --features serde --example export_json --locked -- certificate.pem
cargo run -p x509-info --example binding_dto --locked
```

`details` displays common information; `export_json` owns bounded file reads and JSON
output. Both use only the public model, with no backend parser imports. `binding_dto`
shows a Console-style Rust adapter owning its input and returning application DTOs
that outlive all parser data. An actual FRB integration exposes the adapter DTOs to
Dart and maps typed errors in that binding crate. Dart owns the returned values;
no Rust registry, handle lifecycle or JSON round trip is required. FRB itself stays
outside this crate.

## Dependencies and support

Rust 1.85 or later is required; native and wasm32-unknown-unknown builds are checked.
`x509-parser` and `pem-rfc7468` parse certificates/PEM; `pkcs1` decodes RSA/PSS;
`sha2` computes fingerprints; `hex` formats bytes; `thiserror` supplies typed errors.
`serde` is optional and `serde_json` is only an example/test dependency. There is no
signature-verification backend or async runtime. This package has its own version
within the workspace and remains unpublished while release metadata is finalized.

Original code is Apache-2.0, authored by canokeys.org. The packaged LICENSE covers
original code; LICENSE.console retains the MIT notice for adapted Console code.
