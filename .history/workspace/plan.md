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
and local details/serialization/binding examples are implemented. Consolidation
X1-X3 is implemented with existing APIs, label coverage, decoded fields, raw data,
error distinctions, and summary schema version 1 preserved. Keep the crate and
optional `canokey::x509` re-export as an application adapter over established format
libraries. Independent publication is deferred; retain `publish = false` until
actual usage supports the public contract.

| Stage | Delivered | Acceptance |
| --- | --- | --- |
| X1: OID lookup | Upstream registry used directly; static compatibility labels and independent caller overrides; clones share only immutable base data | Full upstream/label coverage, canonical syntax, override previous values, clone independence, existing summary fixtures |
| X2: Backend conversion | Direct backend GeneralName decoding in the RustCrypto bridge; one owned name projection; existing strict schema/CRL/policy decoding retained | Existing extension fixtures, relative CRL names, nested trailing-data rejection, unknown/malformed and raw-data preservation |
| X3: Application boundary | Existing DTO/JSON examples use the same owned summary after dropping parsing inputs and configuration; usage/contracts/research clarify dependency reuse | Runnable examples without backend imports; unchanged serialization fixtures and all existing format examples retained |

Verified on Rust 1.85.1: default/all-feature workspace tests including doctests
(64/68 passed), formatting, strict workspace/all-target clippy, warning-free
documentation, wasm build, dependency/license checks, all four certificate examples,
and standalone package verification. The JSON example matches the existing golden
fixture. These checks establish local compatibility, not hardware verification or
consumer adoption.

Further extension/cryptography/output-format APIs, a text-printing subsystem,
consumer integration, publication, repository splitting, and upstream changes are
outside this consolidation. Missing standard OIDs can become future upstream
contribution candidates; new features require consumer demand. Issuance,
trust/chain validation, revocation fetching, and policy evaluation remain
application responsibilities. Resume the existing PIV milestones separately.

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
