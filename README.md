# x509-info

Owned X.509 certificate information for applications, independent of CanoKey,
transport, bindings and runtime state. Callers own inputs and results. This crate
turns established parsers' types into certificate details that UI and reporting
code can use without importing ASN.1 types or maintaining OID conversion tables.

Use `x509-parser` directly when its borrowed types fit your application, or
`x509-certificate-printer` for formatted text. This adapter supplies owned data
for details views, binding DTOs, and structured exports.

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
  RSA-PSS parameters/defaults, X25519/X448 and separate parameter/key-encoding status.
- SAN/IAN (DNS, email, IP, URI, directory name, registered ID, OtherName, opaque
  X.400/EDI names), KU, EKU and Basic Constraints.
- SKI/AKI, AIA/SIA access methods and locations, CRL Distribution Points and Freshest CRL.
- Certificate Policies with CPS URIs and preserved UserNotice/private qualifier encodings.
- Raw certificate/name/SPKI/signature/extension data, unknown OIDs and duplicate extension flags.

Unsupported extensions stay `Unsupported`; failed supported extension decoding stays
`Malformed`. Every duplicate OID occurrence is marked, with no first/last-wins policy.
Invalid SAN entries remain visible individually. AKI/AIA/SIA receive complete-schema
checks, and CRL/policy decoding uses RustCrypto types to retain relative CRL names and
reject unconsumed nested data. `Malformed` indicates a supported extension could not
be decoded within the backend's representation (including nested GeneralName/serial
limits); it is not a comprehensive certificate-validity verdict. A malformed supported key encoding
is distinct from an unrecognized algorithm/curve. These findings are not trust decisions.

The parser accepts exactly one bounded DER/PEM certificate (default 1 MiB encoded
input), rejects trailing objects and mismatched inner/outer signature identifiers.
The input budget is not an exact peak-memory bound: full results and summaries own
copies. Parsing does not verify signatures, chains, identities, revocation, critical
extension policy or mathematical key validity. `validity.contains(timestamp)` only
checks the encoded interval; no clock, network, randomness or filesystem is accessed.

## OID names and caller customization

`OidNames::default()` loads the upstream `oid-registry` crypto/X.500/X.509 tables
directly, with static application labels and selected newer standard names taking
precedence. It does not copy the upstream database into a second string map.
The table covers more DN attributes (surname, givenName, title, UID), key purposes (IPsec/IKE and
Microsoft smart-card logon), SHA-224/SHA-3 signatures, hash algorithms, prime curves,
and ML-DSA algorithm identifiers. Unknown OIDs remain available with absent labels.

```rust
use x509_info::{parse_der_with_names, OidNames, ParseOptions};
let mut names = OidNames::default();
names.insert("1.2.3.7", "Internal access endpoint")?;
// Reuse names across calls; results copy labels and never retain this reference.
let info = parse_der_with_names(&der, ParseOptions::default(), &names)?;
```

`parse_pem_with_names` provides the same ownership contract for PEM. `get(oid)` is
also usable independently to label extension, hash or private-policy OIDs. `insert`
validates canonical dotted-decimal syntax, including the first two arcs. No mutable
global registry or callback lifecycle exists. The ordinary parse functions create
one default table per call; reuse a table for repeated inspection. Clones share
only the immutable upstream registry; their custom overrides remain independent.
Lookup precedence is caller overrides, built-in labels, then upstream short names.
For example, `RSA` is a presentation alias, while ML-DSA identifiers supplement
this upstream snapshot; neither kind of label supplies parsing functionality.

Overrides affect structured attribute/algorithm/curve/purpose/access/policy labels;
the backend-generated DN `display` string remains presentation text independent of
these overrides. That formatting uses the backend's immutable default lookup table,
not caller/device state. Labels are not stable identifiers, sanitized markup, decoder
registrations or algorithm-support claims. Adding an ML-DSA name does not enable
ML-DSA key decoding or signature verification. Program logic should use OIDs.

Key encoding/nominal size inspection covers RSA/RSA-PSS, Ed25519/Ed448, X25519/X448,
P-192/224/256/384/521, secp256k1, SM2 and brainpoolP256r1/P384r1/P512r1. Other registry
curve names can still be displayed while size remains unknown. Recognition does
not recommend an algorithm or establish mathematical key validity.

OID references: [upstream registry](https://docs.rs/oid-registry/0.8.1/oid_registry/),
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) for names/extensions,
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) for Ed/Montgomery keys,
[RFC 5639](https://www.rfc-editor.org/rfc/rfc5639.html) for brainpool,
and [NIST algorithm registrations](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration)
for SHA-3 and ML-DSA names. The registry snapshot and crate version determine label coverage.

## GeneralName representation

All nine backend name choices have dedicated owned variants. `OtherName` retains
its type OID, optional caller label, and hex-encoded bytes following the OID,
including the expected explicit [0] value wrapper. The backend extracts the OID
but does not validate that wrapper or decode OID-specific values.

`X400Address` and `EdiPartyName` retain the constructed bit and content octets in
lowercase hex. These are opaque values: `x509-parser` itself does not decode their
inner fields. The outer context tags are [3] and [5]; exact original extension
encoding remains in `ExtensionInfo::value_der`. Invalid names and invalid IP
lengths retain the existing `Malformed(tag)` finding. `Unsupported(tag)` remains
available for compatibility but is not emitted for the current backend choices.

These variants also appear in summaries and Serde output as `other_name`,
`x400_address`, and `edi_party_name`. They replace the former tag-only
`unsupported` findings for these choices; consumers must handle the additional
kinds allowed by schema version 1. Existing variants keep their representation.

## Summary contract

`info.summary()` returns `CertificateSummary`, whose optional Serde representation
has `schema_version: 1`. It omits full DER, raw key/signature/parameter/extension bytes.
Keep `CertificateInfo` when the application needs those encodings. Policy qualifier
value DER and opaque GeneralName contents remain as hex in the summary so
uninterpreted values are not discarded. Only CPS URI has a decoded policy qualifier
variant. Full-result Serde
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

## Other serialization formats

The optional feature supplies `Serialize`, not a built-in JSON engine. Applications
can choose any compatible Serde serializer without changing this crate. CBOR is
tested against the same data model as JSON, including nulls, enum tags, locations
and policies. The summary's hex strings remain strings in CBOR; use an application
DTO/newtype if a different byte representation is required.

TOML cannot represent arbitrary nulls, so the `export_formats` example uses a small
application-owned inventory DTO with selected/renamed fields and omitted None
values. The same approach supports custom JSON, CSV records or schema-based formats.
A caller cannot implement an external trait on an external result type directly
because of Rust's orphan rules; define a local DTO or newtype instead.

No `Deserialize` implementation is promised for certificate results. The format
tests deserialize into application/generic value types, not trusted certificates.
Import actual certificates through DER/PEM parsing. `ciborium`, `toml` and
`serde_json` are dev-dependencies for examples/tests only, not normal library
features or runtime requirements.

## Executable examples

Run from the repository root:

```sh
cargo run -p x509-info --example details --locked
cargo run -p x509-info --features serde --example export_json --locked
cargo run -p x509-info --features serde --example export_json --locked -- certificate.pem
cargo run -p x509-info --example binding_dto --locked
cargo run -p x509-info --features serde --example export_formats --locked
```

`details` displays common information; `export_json` owns bounded file reads and JSON
output. Both use only the public model, with no backend parser imports. `binding_dto`
shows a Console-style Rust adapter owning its input and returning application DTOs
that outlive all parser data. Both it and `export_json` use `CertificateSummary`
after explicitly dropping the input, OID configuration, and full certificate
result. An actual FRB integration exposes the adapter DTOs to Dart and maps typed errors in that binding crate. Dart owns the returned values;
no Rust registry, handle lifecycle or JSON round trip is required. FRB itself stays
outside this crate.

## Dependencies and support

Rust 1.85 or later is required; native and wasm32-unknown-unknown builds are checked.
`x509-parser` and `pem-rfc7468` parse certificates/PEM; backend `GeneralName`
decoding is projected into owned names rather than implemented again.
`pkcs1` decodes RSA/PSS;
`x509-cert` supplies strict AKI/AIA/SIA schema checks and CRL/policy structures;
`oid-registry` supplies the base name tables; `sha2` computes fingerprints;
`hex` formats bytes; `thiserror` supplies typed errors.
`serde` is optional; format serializers are only example/test dependencies. There is no
signature-verification backend or async runtime. This package has its own version
within the workspace and remains unpublished pending evidence from consumer usage.

Original code is Apache-2.0, authored by canokeys.org. The packaged LICENSE covers
original code; LICENSE.console retains the MIT notice for adapted Console code.
