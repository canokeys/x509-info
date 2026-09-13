# x509-info command-line utility

Read one DER/PEM certificate, inspect its fields, or convert its encoding. This
binary lives in the same crate behind the optional `cli` feature and owns
file/standard I/O and serializers. The library has no I/O. No validity, trust, revocation, signature or profile verification
is performed. Inner and outer signature algorithm fields are both retained.

```sh
cargo install --path crates/x509-info --features cli --locked
x509-info certificate.pem
x509-info certificate.der --format json --output report.json
x509-info certificate.pem --format cbor --output report.cbor
x509-info certificate.pem --format toml --summary --output report.toml
x509-info certificate.pem --format der --output certificate.der
x509-info certificate.der --format pem --output certificate.pem
cat certificate.pem | x509-info --format json > report.json
```

Use `cargo run -p x509-info --features cli --locked --` instead of the installed command when
working in this workspace. `--help` lists all arguments. The default encoded input
limit is 1 MiB; override it with `--max-input-bytes`. Multiple certificates and
trailing input are rejected. Auto detection accepts surrounding PEM whitespace;
`--input-format der|pem` explicitly selects an encoding. Paths are platform-native;
`-` means stdin/stdout. Errors go to stderr: argument errors exit with status 2; processing errors with status 1. Output is opened
only after successful parsing and serialization, including for same-path conversion.

Reports include every field in the selected full/summary model plus parsed public
keys, SPKI SHA-256, OtherName/EDI fields, directory-attribute text and available
decoding diagnostics. Opaque/unknown values keep their raw encodings. `--summary`
omits duplicate DER/raw buffers but retains parsed public-key components and opaque
field encodings. `report_version` versions this application report separately from
the library's summary schema. Decoded names are added as `decoded_fields`, or a
`decode_diagnostic` if interpretation fails; original fields remain intact.

JSON and CBOR share the same report model. Text renders all report fields for
humans. TOML omits null object fields, converts unsigned integers above i64::MAX to
decimal strings, and rejects null array elements rather than losing positions.
These are explicit TOML representation differences, not certificate data changes.
SCT timestamps remain milliseconds; certificate/private-key timestamps are seconds.
DER/PEM output preserves the original DER, including its signature, rather than
reconstructing a certificate from a report. Reports cannot be imported as certificates.
