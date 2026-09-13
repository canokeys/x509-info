# Implementation plan

Status: phase 1a foundation implemented; phase 1b includes PIN/PUK, object reads, and certificate reads with bounded gzip decoding. A matching subset of the experimental C ABI exists. Generic DER/PEM inspection is available in the optional x509-info crate, with owned details, common extension decoding, RSA/EC/EdDSA and PSS information, SHA-256 fingerprints and a versioned optional Serde summary. This work is confined to libcanokey; consumer integration requires a separate task. See [README](README.md) for actual APIs and commands, [design](docs/api-design.md) for contracts, and [references](docs/references.md) for evidence.

## Goal and boundaries

Share host protocol encoding, state machines, errors, and firmware compatibility across Console, ckman, and canokey-pkcs11. The library owns PIV/Admin/OATH/OpenPGP protocol logic, pure in-memory protocol cryptography, and reusable certificate format inspection. Certificate trust/issuance policy remains application-owned. Applications own PCSC/USB/WebUSB/NFC/CCID/HID, device enumeration, permissions, connections, locking, runtimes, timeouts, system randomness, clocks, files, UI, and PKCS#11 state.

Caller-owned profiles and operations are the common Rust/binding model. No transport trait, manager, runtime, or mutable global state belongs in the core. The crate responsibilities and dependency graph are maintained in README rather than duplicated here.

## Milestones

| Phase | Deliverables | Acceptance focus |
| --- | --- | --- |
| 1a: foundation | protocol, owned operations, compatibility model, read-only probe, minimal Admin builders | Offline transcripts, bounded parsing/conversations, conservative unknown firmware |
| 1b: PIV | PIN/PUK, management authentication, metadata, keys, private operations, objects/certificates, Batch | Each high-level operation covers SELECT/authentication/target; consumers do not encode APDUs/TLV |
| 1c: first consumer | Complete relevant C ABI and incremental PKCS#11 adoption | Two handle types; typed results; size queries do not sign |
| 1d: reuse | Console FRB, Python binding, ckman PIV adoption | Same core under Dart async and C/Python sync; native/wasm builds |
| 2: Admin | Full device/config/storage information, NFC/NDEF, explicit applet reset | Profile invalidation and partial-write semantics |
| 3: OATH | Credentials, access keys, calculations, legacy/current conversations | Applet-specific continuation, touch, HOTP side effects |
| 4: OpenPGP | DOs, PIN/KDF, keys, certificates, policies, private operations | Independent references, algorithms, authentication, firmware coverage |
| Later evaluation | Additional PIV extensions and shareable FIDO components | Evidence-based enablement; do not force CTAP into APDU operations |

Next PIV work: verify management-key modes against CanoKey evidence, then implement authentication using established block-cipher/comparison dependencies and add authenticated writes; follow with metadata, key generation/import and private operations, and Batch. Extend C bindings alongside useful core increments. Do not add placeholder APIs that always return Unsupported.

Algorithm enums do not promise firmware support. Enable metadata directories, key move/delete, retry configuration, algorithm configuration writes, and ML-KEM decapsulation individually by observed capability. Pending verification is listed in design.

## Generic certificate package

The owned `x509-info` model, configurable OID labels, common extension inspection,
and local details/serialization/binding examples are implemented. The next work
is consolidation, not expansion. Keep the crate and optional `canokey::x509`
re-export as an internal application adapter over established format libraries.
Independent publication is deferred; retain `publish = false` until actual usage
supports the public contract. The stages below are planned, not implemented.

### X1: Simplify OID lookup

- Keep the public `OidNames` API caller-owned. Store the upstream `OidRegistry`
  directly instead of copying its full database into a string map. Use upstream
  lookup helpers where useful; retain only necessary label overrides and missing
  entries. Separate presentation aliases from genuinely missing standard OIDs.
- Preserve canonical OID validation, unknown lookup behavior, `insert` return
  semantics, and current output labels. Labels remain presentation data; dotted
  OIDs determine identity and never select decoders through a name lookup.
- Document ownership precisely: no mutable application registry or retained caller
  references. Dependency-owned immutable lookup tables are distinct from device
  state. Audit DN display separately because it currently uses the backend's
  default registry; do not silently change its formatting or customization scope.

Acceptance: existing OID and summary fixtures remain unchanged; cover independent
caller registries, override precedence/previous values, malformed OIDs, and unknown
OIDs using existing tests where possible. Default construction no longer copies
all upstream entries into owned strings. Candidate commit:
`refactor(x509): reuse the upstream OID registry directly`.

### X2: Reduce backend conversion glue

- Continue using `x509-parser::extensions::GeneralName` for ASN.1 decoding and
  project its borrowed values into the existing owned application types.
- Simplify redundant parsing steps, including the RustCrypto-to-backend name
  bridge where practical. Evaluate direct projection only if it reduces total
  conversion logic without losing raw data or duplicating name handling.
- Retain `x509-cert` where regression tests establish a need: strict nested schema
  checks, relative CRL distribution-point names, and current policy decoding.
  Remove a dependency path only when a simpler replacement passes those cases.
- Preserve public types, errors, unknown/malformed distinctions, duplicate
  extension reporting, raw data, and summary schema version 1. An unavoidable
  observable change must be documented explicitly before implementation.

Acceptance: existing valid/malformed extension and algorithm fixtures pass,
including relative CRL names and nested trailing-data rejection. Add regression
coverage only for behavior affected by the cleanup. Candidate commit:
`refactor(x509): simplify certificate name conversion`.

### X3: Validate the application boundary and document scope

- Refine the existing binding DTO and structured export examples instead of
  creating parallel examples. Both must use the same public application model
  without importing backend ASN.1 types. Show that results survive dropping input
  bytes and caller-owned OID configuration.
- Keep the Rust model primary and Serde optional. JSON/CBOR/TOML serializers and
  application DTO choices belong in examples/callers, not new library format APIs.
  Preserve useful existing examples; the details example demonstrates fields,
  rather than becoming a general certificate pretty-printer.
- Update the package README, design, and ecosystem assessment with their distinct
  responsibilities: usage, contracts, and evidence. Explain when direct use of
  `x509-parser` or `x509-certificate-printer` is sufficient. Do not claim that owned
  types, OID labels, or Serde support alone establish uniqueness.

Acceptance: run the two application examples and verify existing serialization
fixtures. They must demonstrate reusable field conversion and explicit ownership
without transport, FRB, clocks, or global application state. Record any remaining
backend-specific application glue as a concrete gap. Candidate commit:
`docs(x509): clarify the application adapter boundary`.

### Consolidation checks and stop conditions

For Rust changes, run formatting, default/all-feature tests and doctests, strict
workspace/all-target clippy, and warning-free public documentation builds. At the
end, verify wasm, dependency boundaries, and standalone package contents/build.
Reuse existing fixtures; this work does not establish hardware or consumer
integration compatibility.

Do not add more extensions, cryptography, output-format APIs, or a text-printing
subsystem during consolidation. No consumer integration, publication, repository
split, or upstream modification is included. Missing standard OIDs can be recorded
as future upstream contribution candidates. Issuance, trust/chain validation,
revocation fetching, and policy evaluation remain application responsibilities.

Completion means simpler internals with preserved application contracts and two
convincing local usage examples. Publication is a later decision based on real
consumer usage and maintenance value, not OID counts or feature breadth. Resume
the existing PIV milestones separately after this focused work.

## Engineering and delivery

The first version need not be no_std; prioritize no platform I/O, no runtime, and wasm compatibility. Reuse established pure in-memory cryptography, compression, and standard key-format dependencies rather than implementing primitives. Selection criteria and candidates are maintained in [design](docs/api-design.md#dependency-reuse). PCSC, USB/HID, Tokio, FRB, and PyO3 must stay out of the core dependency closure. Add future applet/binding crates only when implemented; PyO3 belongs exclusively in its binding crate.

Rust uses SemVer; C ABI major/minor is independent; a future Python public version follows the library major. Freeze the C ABI only after its complete header and implementation are validated. The current ABI is experimental 0.1. Firmware protocol variants are unrelated to package versions.

Deliver coherent buildable stages with Conventional Commits. Repository text, comments, examples, and CI messages are English. Examples must execute against validated transcripts, show application-owned state and cleanup, and remain part of CI. Keep the current Actions revisions pinned separately from the intentional compiler/MSRV choice.

## Future migration

Validate PIV adoption in the order PKCS#11, Console, ckman. Existing and new paths may coexist behind a build switch until each feature is replaced. Disable consumer APDU continuation and serialize all old/new paths through one device lock and connection lifecycle. Never insert application identity queries or SELECT inside an operation.

Reference clones are read-only evidence, not dependencies or proof of all firmware support. Integration and upstream modifications are out of scope for the current implementation task.

## Acceptance matrix

| Layer | Required checks |
| --- | --- |
| Codecs | APDU golden vectors, TLV bounds, certificate containers, key/signature formats as implemented |
| Operations | SELECT/auth order, 61xx/6Cxx, chaining, failures, cancellation, budgets; Batch partial progress when implemented |
| Compatibility | Version rules, historical IDs/containers/empty-slot statuses, unknown versions, evidence provenance |
| Bindings | C ownership, buffer queries, errors and cleanup; FRB native/wasm and Python typed results when implemented |
| Integration | Controlled usbip/hardware tests across stable, previous and next firmware, independent application transport |
| Engineering | fmt, strict clippy, public rustdoc coverage and warning-free documentation builds, doctests, relevant tests, C/C++ linking, wasm, dependency checks, parser fuzz smoke, runnable examples |

Phase 1 as a whole is complete only when all three consumers can reuse the same PIV implementation while retaining their own application state and connections. Current offline tests establish neither full phase 1 completion nor hardware compatibility.
