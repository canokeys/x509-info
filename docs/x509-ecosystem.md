# Ecosystem and dependency choices

`x509-info` is an owned, transport-free projection for applications and reports.
It reuses established parsers and keeps unknown or malformed values with typed
diagnostics. It does not verify signatures, trust chains, identities or policy.

## Comparisons

| Project | Best fit | Why use `x509-info` instead |
| --- | --- | --- |
| [x509-parser](https://crates.io/crates/x509-parser) | Borrowed parsing and low-level inspection | Owned results, stable summaries, diagnostics and report schemas |
| [x509-cert](https://crates.io/crates/x509-cert) | RustCrypto ASN.1 models, encoding and construction | Application-facing projection and CLI formats |
| [x509-certificate](https://crates.io/crates/x509-certificate) | High-level owned certificates and crypto operations | Narrow inspection layer without I/O, clocks or verification |
| [picky-asn1-x509](https://crates.io/crates/picky-asn1-x509) | Picky ASN.1 structures with Serde | Certificate reading and a versioned report contract |
| [x509-certificate-printer](https://crates.io/crates/x509-certificate-printer) | Human-readable certificate text | Library data for bindings plus text and machine-readable output |
| [cert-dump](https://crates.io/crates/cert-dump) | Scanning stores and producing inventory JSON | One certificate at a time, with no filesystem, database or scanner |

These projects overlap in certificate decoding or presentation, but their data
ownership, validation scope and output contracts differ. `rcgen` is for creating
certificates, while `rustls-pki-types` supplies shared PKI byte/time types; they
are complementary rather than replacements.

## Primary sources

- [x509-parser API](https://docs.rs/x509-parser)
- [RustCrypto x509-cert](https://docs.rs/x509-cert)
- [Picky ASN.1 X.509](https://docs.rs/picky-asn1-x509)
- [Certificate printer](https://docs.rs/x509-certificate-printer)
- [cert-dump](https://docs.rs/cert-dump)
