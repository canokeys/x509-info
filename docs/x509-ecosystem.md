# X.509 inspection ecosystem and publication options

Research date: 2026-09-13. This is a publication/design assessment, not a rename or release. The current package remains `canokey-x509` with `publish = false`.

## Recommendation

A neutral package name is appropriate: the current crate has no PIV, APDU, CanoKey compatibility, transport or binding dependency. Its reusable responsibility is **owned certificate inspection data for applications**, backed by established parsers. Recommend `x509-inspect` as the first naming candidate, with `x509-info` as an alternative.

A generic X.509 parser or ASN.1 model already has strong alternatives. Owned structs and Serde support alone are not a unique contribution. A separately maintained inspection library is justified if it supplies a well-defined, convenient application data model, common extension interpretation, predictable handling of unknown data, and documented serialization. Renaming the existing adapter without developing that contract would offer only modest differentiation.

Keep the existing parser backend for the first iteration rather than switching merely to justify a new name. If the intended direction becomes certificate construction, DER round trips or a comprehensive RFC 5280 type model, use/evaluate RustCrypto `x509-cert` directly instead of expanding this adapter into another format implementation.

## Evidence and method

Queried the live crates.io API for X.509, certificate inspection, certificate metadata, and JSON/Serde-related packages. Recorded latest non-prerelease versions, features, declared MSRV, licenses and repository URLs. Inspected published source archives for `x509-cert`, `x509-certificate`, `picky-asn1-x509`, `synta-certificate`, `x509-certificate-printer`, `cert-dump` and `inspect-cert-chain`, plus the locally resolved `x509-parser` and the current workspace implementation.

The comparisons below describe the inspected versions, not all possible wrappers around them. Searches are not exhaustive and do not establish that no equivalent crate exists. Competitor feature combinations were not built or benchmarked. MSRV entries are package declarations; their resolved dependencies can impose additional constraints. Download counts were not used as a quality or security verdict.

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

## Current implementation versus a public inspection contract

Already suitable for reuse:

- No dependency on the other workspace crates; only metadata and `thiserror` configuration are inherited.
- Owned result fields with typed parsing errors and optional Serialize.
- Strict single-certificate PEM consumption, DER trailing-data rejection, and a caller-controlled input-size limit.
- Separate encoded key-bit count and algorithm-specific size; explicit unknown values and correct nominal P-521 handling.
- Original DER/name/SPKI/extension bytes retained; timestamps supplied/read as values, without querying the system clock.
- Existing native/wasm checks and attribution for adapted Console code.

The current surface still reflects an initial adapter. Before defining the first public contract, address or explicitly delimit:

1. **Useful structured inspection.** Names currently expose display text plus DER; extensions are raw OID/critical/value triples. For UI/FFI/reporting differentiation, prioritize structured RDN attributes, SAN, Key Usage, Extended Key Usage and Basic Constraints while preserving unsupported raw values. Consumers should not need a second ASN.1 parser for the most common display fields.
2. **Serialization semantics.** Today's JSON includes all raw bytes as numeric arrays. Choose a documented compact summary versus full-data representation, byte encoding, timestamp representation and treatment of unknown/unsupported fields. Do not change the existing internal format incidentally; define any public representation deliberately. Serde implementation alone is not a stable cross-language schema.
3. **Inspection versus validation.** Parsing does not imply trusted identity, valid signatures, valid EC points or accepted critical extensions. Decide whether semantic anomalies such as mismatched inner/outer signature algorithms are inspection findings or fatal errors; the current implementation rejects that mismatch. Do not call it a trust verifier or a full PKI toolkit.
4. **Release contract and evidence.** Make public result/error types extensible, document MSRV/features, and add targeted coverage for common extensions and mixed/unknown algorithm families. The input limit is not a claim of zero-copy behavior or an exact peak-memory limit. Keep parser/format work in dependencies.

This can be a small 0.1 crate with a clearly limited scope; it does not need every PKI feature before a first release. The useful release criterion is a coherent reusable contract, not a large feature count. If the intended scope remains only today's few getters for Console, keeping the adapter internal or contributing a helper upstream would also be reasonable.

## Naming and packaging

Exact crates.io API lookups on the research date returned HTTP 404 for `x509-inspect`, `x509-info`, `cert-inspect`, `certificate-info`, `x509-metadata`, and `x5092json`. This means no package was found through those lookups at that time; it is not a name reservation or a guarantee that publication will accept the name. `certinfo` is already used by a TLS-information CLI. Hyphen/underscore variants should not be treated as independent naming opportunities.

Prefer **`x509-inspect`**: it describes the actual operation and leaves room for useful structured findings without promising verification. `x509-info` is a reasonable shorter alternative. Avoid an overly broad `x509`/`x509-utils` identity and a JSON-specific name when Rust/FRB structures remain primary. Crate name and author are independent; `authors = ["canokeys.org"]` remains appropriate under a neutral name.

Independent publication does not require a new repository immediately. A generic package can stay in this workspace, have its own package identity/version/release cadence, and be depended on by libcanokey. Proposed direction:

```text
canokey --optional feature--> x509-inspect --> established X.509/PEM parsers
other applications ---------> x509-inspect
```

`canokey::x509` can remain the facade re-export, so consumers need not change that namespace when the package is renamed. A path-plus-version dependency can support local development and a future published dependency. A separate repository is useful only if independent governance/issues/releases warrant it.

A subsequent implementation/release task should set the neutral package identity, package-specific README/repository/documentation metadata and version policy; verify the packaged license and retained `LICENSE.console`; test an extracted package on the advertised MSRV and wasm feature combinations; and publish only after the package is ready. This research does not remove `publish = false`, reserve a crate name, contact maintainers, or publish anything.

## Primary source pointers

- [x509-parser certificate API](https://docs.rs/x509-parser/0.18.1/x509_parser/certificate/struct.X509Certificate.html) and [features](https://docs.rs/crate/x509-parser/0.18.1/features).
- [RustCrypto x509-cert published source](https://docs.rs/crate/x509-cert/0.3.0/source/src/certificate.rs) and [features](https://docs.rs/crate/x509-cert/0.3.0/features).
- [x509-certificate published manifest](https://docs.rs/crate/x509-certificate/0.25.0/source/Cargo.toml) and [owned certificate source](https://docs.rs/crate/x509-certificate/0.25.0/source/src/certificate.rs).
- [picky-asn1-x509 README](https://docs.rs/crate/picky-asn1-x509/0.15.4/source/README.md) and [Serde certificate types](https://docs.rs/crate/picky-asn1-x509/0.15.4/source/src/certificate.rs).
- [synta-certificate features](https://docs.rs/crate/synta-certificate/0.3.3/features) and [README](https://docs.rs/crate/synta-certificate/0.3.3/source/README.md).
- [Certificate printer source](https://docs.rs/crate/x509-certificate-printer/0.1.0/source/src/lib.rs).
- [cert-dump JSON model](https://docs.rs/crate/cert-dump/3.0.1/source/src/json_output.rs) and [published manifest](https://docs.rs/crate/cert-dump/3.0.1/source/Cargo.toml).
- [inspect-cert-chain published source](https://docs.rs/crate/inspect-cert-chain/0.0.35/source/).
- [Cargo package selection and packaging](https://doc.rust-lang.org/cargo/commands/cargo-package.html), [manifest package metadata](https://doc.rust-lang.org/cargo/reference/manifest.html#the-package-section), and [workspace inheritance](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-package-table).
