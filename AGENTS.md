# Repository guidance

- Write code, comments, rustdoc, diagnostics and documentation in English.
- Keep certificate models and ASN.1 interpretation in lib/. Keep CLI arguments, I/O, formatting and report schemas in bin/. This is one independent crate.
- Callers own inputs, results and OID overrides. Do not add mutable globals, handle registries, clocks, randomness, transports or async runtimes to the library.
- Parse fields and encodings without enforcing validity, trust, signatures, identity or attestation policy. Preserve unknown and malformed data with typed diagnostics.
- Reuse maintained parsing and cryptography libraries. Preserve Rust 1.85 compatibility and the default/serde/schema/cli feature boundaries.
- Keep deny(missing_docs), document public ownership and encoding contracts, and avoid exposing backend borrowing through owned results.
- Library summary and CLI report versions are separate contracts. Preserve existing representations; incompatible changes require a version bump. Generate CLI schemas from source types and shared formatting rules.
- Before Rust commits, run fmt, default/all-feature tests including doctests, strict all-target clippy and rustdoc with warnings denied. Run dependency, schema, wasm and package checks when affected. Test meaningful malformed-input and representation cases.
- Maintain Rust 1.85 as the MSRV. The MSRV CI job runs the default test suite; the latest stable job runs all-feature tests, clippy, documentation, wasm, dependency, schema and packaging checks. Dependency upgrades must remain compatible with the MSRV unless a deliberate MSRV increase is documented in the release notes.
- Use Conventional Commits and the configured Git identity. Review staged changes and git diff --check. Exclude build artifacts, caches, private keys and credentials.
- Keep the package licensed under Apache-2.0. README owns usage and release setup; docs/x509-ecosystem.md owns the detailed dependency comparison.
