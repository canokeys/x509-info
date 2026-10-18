# Changelog

## [Unreleased]

- **MSRV is now Rust 1.88** (from 1.85), so the `mtcs` dependency can use the
  current RustCrypto generation (sha2 0.11, ctutils 0.4.3).
- Recognized Merkle Tree Certificate structures (draft-ietf-plants-merkle-tree-certs):
  MTCProof decoding via `CertificateInfo::mtc_proof`, the (log number, entry index)
  serial split via `mtc_entry_reference`, RELATIVE-OID trust anchor ID attribute
  text, and the MTCCertificationAuthority extension.
- PEM inputs now accept one CERTIFICATE PROPERTIES block alongside the certificate,
  retained raw as `CertificateInfo::certificate_properties`. Duplicate block kinds
  and other labels remain errors.
- CLI reports carry an optional `mtc` section and the properties block; the report
  version is unchanged.
- MTC wire-format parsing is delegated to the `mtcs` crate's no-cryptography base
  layer (path dependency during development; publishing this crate requires
  publishing `mtcs` first).

## 0.1.1

- Documented supported certificate and report formats.
- Added CI caching and explicit MSRV/stable toolchain jobs.
- Simplified the ecosystem comparison.

## 0.1.0

- Initial release of the owned X.509 inspection library and CLI.
