# x509-info

[![CI](https://github.com/canokeys/x509-info/actions/workflows/ci.yml/badge.svg)](https://github.com/canokeys/x509-info/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/x509-info.svg)](https://crates.io/crates/x509-info)
[![docs.rs](https://docs.rs/x509-info/badge.svg)](https://docs.rs/x509-info)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Owned X.509 certificate data for applications, bindings and reports. Parse DER or
PEM into names, algorithms, public-key components and decoded extensions, including
FIDO identifiers. Unknown fields retain their original encodings and diagnostics.

The library performs no I/O, reads no clock, and verifies no signatures, trust chains
or attestation policy. Callers own all inputs, results and OID overrides.

## Why this crate?

| Library | Focus |
| --- | --- |
| x509-parser | Borrowed certificate types and low-level parsing; used internally |
| x509-cert | RustCrypto ASN.1 structures and certificate construction; nested decoders reused here |
| x509-certificate-printer | Formatted certificate text |
| x509-info | Owned application data, field diagnostics, versioned reports and generated schemas |

See the [ecosystem comparison](docs/x509-ecosystem.md) for alternatives and dependency choices.

## Library

Requires Rust 1.85+.

```toml
[dependencies]
x509-info = { version = "0.1.0", features = ["serde"] }
serde_json = "1"
```

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = std::fs::read("certificate.pem")?;
    let cert = x509_info::parse_pem(&pem, Default::default())?;
    println!("{}", serde_json::to_string_pretty(&cert.summary())?);
    Ok(())
}
```

Inputs are limited to one certificate and 1 MiB by default; use `ParseOptions` to
change the byte limit. The full result retains original bytes; `summary()` creates
an owned view without large raw buffers. Public-key and name `details()` accessors
provide additional decoded fields.

| Feature | Adds |
| --- | --- |
| Default | Parsing and owned Rust results |
| `serde` | Serialization of library results |
| `schema` | Schemars schemas for the library's Serde model |
| `cli` | Binary, format serializers and CLI report schemas |

Use `cargo doc --all-features --no-deps --open` for API documentation and
`cargo run --example binding_dto` for a binding example.

## CLI

```sh
cargo install x509-info --features cli --locked
x509-info certificate.pem
x509-info certificate.pem --format json --summary
x509-info certificate.pem --format yaml -o report.yaml
x509-info certificate.pem --format der -o certificate.der
x509-info --schema -o report.schema.json
x509-info --schema --summary -o summary.schema.json
```

Formats: text, JSON, JSON Lines, YAML, TOML, CBOR, MessagePack, DER and PEM.
Omit the input path or use `-` for stdin. Textual reports use Base64 for raw blocks,
hex for numerical components and fingerprints, and UUID strings for AAGUIDs.
CBOR and MessagePack use native byte strings. DER/PEM conversion preserves the DER.

[CLI usage](bin/README.md) · [Report schemas and format contracts](bin/SCHEMA.md)

## Layout and development

```text
lib/        Parsing and models; names/, keys/ and extensions/ submodules
bin/        CLI, report formatting and schema generation
examples/   Binding DTO example
tests/      Integration tests and synthetic certificate fixtures
```

```sh
cargo fmt --all --check
cargo test --locked
cargo test --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Licensed under [Apache-2.0](LICENSE).
