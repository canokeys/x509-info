# X.509 dependency choices

Sources inspected on 2026-09-13. Comparisons describe the listed releases, not all
versions or wrappers; alternatives were not benchmarked. Current APIs and limits
are documented in the [package README](../../crates/x509-info/README.md).

## Reuse boundary

`x509-info` projects established parser types into owned application data for
bindings and reports. `x509-parser` provides certificate and GeneralName decoding;
`oid-registry` provides OID names. The `x509_parser::objects` short-name/description
helpers query that same registry and can accept caller-owned tables. Maintaining
a second general-purpose parser or OID database would duplicate those libraries.

RustCrypto `x509-cert` supplies strict nested schema checks and CRL/policy types.
Regression fixtures cover nested trailing data and relative CRL names that the
current `x509-parser` path cannot handle equivalently. Retain those paths until a
replacement preserves their behavior.

`x509-certificate-printer` exposes `PrettyPrinter::pretty_print` and `to_pem` as
strings; formatting helpers are private. Use it directly for text output. The
owned application/summary model is useful for typed bindings and serialization,
but neither ownership nor Serde alone is unique. Publication remains deferred
pending actual consumer usage.

## Main alternatives

| Package and inspected version | Existing responsibility | Ownership / serialization observations | Consequence for this project |
| --- | --- | --- | --- |
| [`x509-parser` 0.18.1](https://crates.io/crates/x509-parser/0.18.1) | X.509 parsing, extensions and low-level certificate inspection | Main certificate type borrows input; no Serde feature in this release. Optional verification backends are separate features | Current backend. An application-facing owned projection can add value without duplicating its parser |
| [`x509-cert` 0.3.0](https://crates.io/crates/x509-cert/0.3.0) | RustCrypto RFC 5280 certificate model, DER/PEM encoding/decoding and optional builders | Owned certificate model; `no_std` base, default PEM/std features; no Serde feature in this release | Strongest alternative when callers want standard certificate types or format construction. Ownership alone does not distinguish our crate |
| [`x509-certificate` 0.25.0](https://crates.io/crates/x509-certificate/0.25.0) | Parsing, owned/captured certificates, convenience getters, signing/verification and construction | `X509Certificate` and `CapturedX509Certificate` own data; inspected normal dependencies include nonoptional `ring` and `chrono` with clock support; no Serde dependency in this release | Already provides a higher-level owned API, but has a broader cryptographic/runtime surface than our no-I/O inspection layer |
| [`picky-asn1-x509` 0.15.4](https://crates.io/crates/picky-asn1-x509/0.15.4) | Low-level X.509/related ASN.1 types used by the Picky ecosystem | Certificate derives Serialize/Deserialize. The README explicitly positions these wrappers for `picky-asn1-der`, rather than an easy certificate-reading API | Direct evidence that "X.509 structs with Serde" is not an empty category. Its ASN.1 representation differs from a stable UI/report summary schema |
| [`synta-certificate` 0.3.3](https://crates.io/crates/synta-certificate/0.3.3) | Broad X.509/PKI certificate structures, builders and related operations | Optional Serde; supports reduced no_std/alloc configurations. Default features include OpenSSL and PQC, so defaults are not our desired dependency boundary | Another existing general model with serialization. Assess minimal features before considering it; do not describe native dependencies as unavoidable |

Declared MSRV/license snapshots: `x509-parser` 1.67.1, MIT OR Apache-2.0; `x509-cert` 1.85, Apache-2.0 OR MIT; `x509-certificate` 1.85, MPL-2.0; `picky-asn1-x509` 1.85, MIT OR Apache-2.0. `synta-certificate` did not declare an MSRV in the returned version metadata; its license is MIT OR Apache-2.0. These are compatibility facts, not reasons to dismiss an otherwise suitable library.

## Nearby inspection/report tools

| Package | What overlaps | What differs |
| --- | --- | --- |
| [`x509-certificate-printer` 0.1.0](https://crates.io/crates/x509-certificate-printer/0.1.0) | Reuses x509-parser to present certificate details, including extensions | Library exposes `PrettyPrinter::pretty_print() -> String` and `to_pem() -> String`, rather than our owned information model |
| [`cert-dump` 3.0.1](https://crates.io/crates/cert-dump/3.0.1) | Has `ParsedCert`, a Serde `JsonCertificate`, and NDJSON certificate metadata | Published manifest contains a binary target, not a library target. Its schema includes scan path/offset/source/duplicate tracking, with filesystem/scanner/SQLite concerns |
| [`inspect-cert-chain` 0.0.35](https://crates.io/crates/inspect-cert-chain/0.0.35) | Human-readable certificate/extension inspection | CLI for files/stdin/remote hosts and chain debugging; published source has a binary entry point. Declared MSRV 1.93 |

`cert-dump` is especially relevant: certificate-to-JSON functionality already exists. The narrower opportunity is an embeddable, transport-free library with an application-neutral schema, not a claim to invent certificate JSON.

For other goals, [`rcgen` 0.14.10](https://crates.io/crates/rcgen/0.14.10) focuses on certificate generation, and [`rustls-pki-types` 1.15.1](https://crates.io/crates/rustls-pki-types/1.15.1) provides shared PKI byte/time types rather than a full inspection report. They are adjacent building blocks, not direct replacements for this use case. The Picky project's latest stable `picky` version is not the same release stream as its current ASN.1 subcrates; comparing only the old stable high-level version would misrepresent that ecosystem.

## Primary source pointers

- [x509-parser certificate API](https://docs.rs/x509-parser/0.18.1/x509_parser/certificate/struct.X509Certificate.html) and [features](https://docs.rs/crate/x509-parser/0.18.1/features).
- [RustCrypto x509-cert published source](https://docs.rs/crate/x509-cert/0.3.0/source/src/certificate.rs) and [features](https://docs.rs/crate/x509-cert/0.3.0/features).
- [x509-certificate published manifest](https://docs.rs/crate/x509-certificate/0.25.0/source/Cargo.toml) and [owned certificate source](https://docs.rs/crate/x509-certificate/0.25.0/source/src/certificate.rs).
- [picky-asn1-x509 README](https://docs.rs/crate/picky-asn1-x509/0.15.4/source/README.md) and [Serde certificate types](https://docs.rs/crate/picky-asn1-x509/0.15.4/source/src/certificate.rs).
- [synta-certificate features](https://docs.rs/crate/synta-certificate/0.3.3/features) and [README](https://docs.rs/crate/synta-certificate/0.3.3/source/README.md).
- [Certificate printer source](https://docs.rs/crate/x509-certificate-printer/0.1.0/source/src/lib.rs).
- [cert-dump JSON model](https://docs.rs/crate/cert-dump/3.0.1/source/src/json_output.rs) and [published manifest](https://docs.rs/crate/cert-dump/3.0.1/source/Cargo.toml).
- [inspect-cert-chain published source](https://docs.rs/crate/inspect-cert-chain/0.0.35/source/).
