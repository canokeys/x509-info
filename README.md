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
- Certificate Policies with CPS URIs, structured UserNotice and retained qualifier encodings.
- Name Constraints, Policy Constraints/Mappings and Inhibit Any Policy.
- Private Key Usage Period and multi-valued Subject Directory Attributes.
- TLS Feature numbers, OCSP no-check, CT poison and embedded SCT lists.
- Netscape certificate-type flags and comments.
- FIDO AAGUID/transport bits and Microsoft template name/OID/version fields.
- RSA components, SEC1 coordinates/compressed points, Ed/Montgomery encodings and SPKI SHA-256.
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
input) and rejects trailing objects. Inner/outer signature identifiers are retained
independently; disagreement does not cause a parse failure.
The input budget is not an exact peak-memory bound: full results and summaries own
copies. Parsing does not verify signatures, chains, identities, revocation, critical
extension policy or mathematical key validity. `validity.contains(timestamp)` only
checks the encoded interval; no clock, network, randomness or filesystem is accessed.

## Additional extension fields

| Extension | OID | Representation |
| --- | --- | --- |
| Name Constraints | 2.5.29.30 | Ordered permitted/excluded subtrees with minimum/maximum; IP address and mask remain separate |
| Policy Constraints | 2.5.29.36 | Optional explicit-policy and mapping-inhibition counters |
| Policy Mappings | 2.5.29.33 | Ordered issuer/subject OID pairs and labels, preserving duplicates |
| Inhibit Any Policy | 2.5.29.54 | skipCerts counter |
| Private Key Usage Period | 2.5.29.16 | Optional Unix-second bounds, separate from certificate validity |
| Subject Directory Attributes | 2.5.29.9 | Attribute OIDs/labels and complete DER values in encoded SET order |
| TLS Feature | 1.3.6.1.5.5.7.1.24 | u16 numbers including unknowns/duplicates; 5=status_request, 17=status_request_v2 |
| OCSP no-check | 1.3.6.1.5.5.7.48.1.5 | NULL marker; does not disable revocation checks |
| CT poison | 1.3.6.1.4.1.11129.2.4.3 | NULL marker; does not establish precertificate eligibility |
| SCT list | 1.3.6.1.4.1.11129.2.4.2 | v1 log ID, Unix milliseconds, extensions, algorithm numbers and signature; unknown versions retain entry bytes |
| Netscape certificate type | 2.16.840.1.113730.1.1 | Eight flags, including the reserved bit |
| Netscape comment | 2.16.840.1.113730.1.13 | IA5 text without markup sanitization |

These fields appear in both full results and summaries. Counters/distances use
u32; values outside the backend representation produce `Malformed`. The strict
RustCrypto name-constraint decoder does not support X.400 bases; other choices
reuse the owned name projection. IP constraints accept 8/32-byte address+mask
encodings, preserve host bits and noncontiguous masks, and expose other lengths
as `MalformedIp` with retained bytes. They never use SAN host-address conversion.
Private-key times follow the backend's 1970–9999 year range; bounds are not checked
against certificate validity or the current clock.

SCT list, entry, and DER lengths must be consumed exactly. Unknown SCT versions
remain opaque, and unknown v1 algorithm numbers remain numeric. No CT log lookup,
signature verification, TLS enforcement, name matching, or policy-path processing
occurs. CRL/CRL-entry extensions require a separate CRL inspection API and remain
uninterpreted here. UserNotice also exposes organization, ordered INTEGER notice
numbers and explicit text; unknown qualifiers retain their raw form.

## Device identifiers and additional field accessors

FIDO AAGUID (`1.3.6.1.4.1.45724.1.1.4`) retains OCTET STRING bytes in hex, even when
the length differs from the FIDO profile. U2F transports (`1.3.6.1.4.1.45724.2.1.1`)
expose Bluetooth Classic/LE, USB, NFC, internal and unknown set bits. No device or
attestation-profile matching occurs. Microsoft template name (`1.3.6.1.4.1.311.20.2`)
is BMP text; template information (`1.3.6.1.4.1.311.21.7`) retains its OID and
optional version INTEGERs. `IntegerValue` preserves signed content and supplies
an optional i64 value without rejecting larger numbers.

- `GeneralName::details()` decodes UPN, HardwareModuleName, DNS SRV, XMPP and EDI
  fields from retained bytes. Unknown OtherName OIDs return None. Raw encodings
  remain unchanged; this optional accessor never caches results.
- DN values decode UTF8, Printable, Numeric, IA5, Visible, BMP and Universal strings.
  `DirectoryAttribute::text_values()` provides the same decoding per value. No
  ambiguous Teletex character-set interpretation is guessed by this text helper.
- UserNotice follows the RFC 5280 schema using generic dependency ASN.1 decoders:
  the current x509-cert UserNotice type has an incorrect noticeRef type and partial
  DisplayText coverage. This adapter supports all four DisplayText encodings and
  preserves signed, duplicate, and large notice numbers without display policy.
- `PublicKeyInfo::details()` extracts RSA modulus/exponent, SEC1 x/y or compressed
  x/parity, and RFC 8410 encoded keys. It performs no primality, curve arithmetic,
  decompression or strength check. `spki_sha256_fingerprint()` hashes the original
  complete SPKI encoding, including parameters.
- `NameAttribute::diagnostic()`, `PolicyQualifier::diagnostic()` and
  `ExtensionInfo::diagnostic()` expose typed decoding causes where available.
  `Unclassified` explicitly preserves uncertainty from older backend paths.
  Existing Malformed/Unsupported states are retained for compatibility.

See [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html),
[RFC 4108](https://www.rfc-editor.org/rfc/rfc4108.html),
[WebAuthn attestation](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation),
and [Microsoft template fields](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cx509extensiontemplate).

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
including the expected explicit [0] value wrapper. The initial projection extracts the OID; `details()` optionally decodes supported
OID-specific values and checks their wrappers.

`X400Address` and `EdiPartyName` retain the constructed bit and content octets in
lowercase hex. EDI fields are available through `details()` using RustCrypto;
X.400 internals remain unparsed. The outer context tags are [3] and [5]; exact original extension
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
value DER, opaque GeneralName contents, directory-attribute values, and SCT
byte fields remain as hex in the summary so uninterpreted values are not discarded. CPS URI and UserNotice have decoded policy qualifier variants. Full-result Serde
is also available, but is a diagnostic representation tied to crate SemVer, not the
versioned summary contract.

- Byte values in the summary use lowercase unseparated hex. Serial hex preserves
  the original INTEGER content, including sign padding. Name attribute value hex
  preserves unsupported string encodings without lossy conversion.
- Certificate/private-key times are signed Unix seconds; SCT `timestamp_unix_ms`
  is unsigned Unix milliseconds. OIDs use dotted decimal. Missing/unknown optional
  values serialize as null. RDNs are arrays of attribute arrays, not flattened maps.
- Enums use snake_case `kind`/`value` tags; status enums use snake_case strings.
  Consumers must tolerate additional fields and unknown kinds/statuses. Incompatible
  representation changes require a new schema major. JSON object order is not a contract.
- Names/labels are presentation conveniences; do not compare identities by display
  strings. UTF8/Printable/Numeric/IA5/Visible/BMP/Universal values are decoded; other encodings retain
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

TOML has no null and cannot represent every u64. The CLI documents its omission
and decimal-string conventions. Applications can instead use their own DTO/newtype
for a different schema; serializers remain outside the library's normal dependencies.
No `Deserialize` is provided for certificate results. Import certificates through
DER/PEM parsing; report deserialization does not reconstruct a trusted certificate.

## Command-line utility and binding example

The [x509-info binary](bin/README.md) replaces the details and export
examples. It supports text, JSON, CBOR, TOML and DER/PEM conversion, file/stdin
input, bounded reads, and file/stdout output. Reports include the additional
name/key accessors and available diagnostics as well as the core result fields.

```sh
cargo run -p x509-info --features cli --locked -- certificate.pem --format json
cargo run -p x509-info --features cli --locked -- certificate.pem --format toml --summary
cargo run -p x509-info --features cli --locked -- certificate.der --format pem -o certificate.pem
cargo run -p x509-info --example binding_dto --locked
```

The binding example returns a Console-style application DTO after dropping the
input, OID configuration, and full certificate result. Actual FRB adapters expose
DTOs and typed errors; Dart owns the values with no JSON round trip or Rust handle
registry. FRB remains outside this crate.

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


## Source layout and features

The package contains a library and an optional binary. Cargo explicitly selects
their entry points; public library types remain re-exported from the crate root.

```text
lib/
  mod.rs          Certificate model, parsing entry points, public re-exports
  decoding.rs     Shared encoding helpers and diagnostics
  oids.rs         OID names and caller-owned overrides
  summary.rs      Owned summary and serialization contract
  names/          Distinguished names and GeneralName details
  keys/           Algorithms, parameters and public-key fields
  extensions/     Standard, device, policy and transparency extensions
  tests/          Internal decoder tests
bin/
  main.rs         clap arguments, bounded input and output
  report.rs       Report enrichment and text/JSON/CBOR/TOML rendering
  encoding.rs     Base64/native byte fields and UUID display for CLI reports
  README.md       Command-line usage
tests/            Integration tests and certificate fixtures
examples/         Binding DTO example
```

Default features build only the library. `serde` adds serialization of owned
types; `cli` enables `serde`, clap and the binary's format serializers. Library
consumers and the CanoKey facade do not enable `cli`. The binary uses only public
library APIs; ASN.1 interpretation belongs in `lib/`.
