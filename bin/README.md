# x509-info command-line utility

Read one DER/PEM certificate, inspect its fields, or convert its encoding. This
binary lives in the same crate behind the optional `cli` feature and owns
file/standard I/O and serializers. The library has no I/O. No validity, trust, revocation, signature or profile verification
is performed. Inner and outer signature algorithm fields are both retained.

```sh
cargo install --path crates/x509-info --features cli --locked
x509-info certificate.pem
x509-info certificate.der --format json --output report.json
x509-info certificate.pem --format yaml --output report.yaml
x509-info certificate.pem --format jsonl --output report.jsonl
x509-info certificate.pem --format messagepack --output report.msgpack
x509-info --schema --output report.schema.json
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
the library's summary schema. The current report version is 2. Decoded names use
`decoded_fields`, or `decode_diagnostic` if interpretation fails; original encodings
remain available in the representations below.

Text, JSON, JSON Lines, YAML and TOML use standard padded Base64 without embedded line breaks for
raw encoding blocks, including certificate/name/SPKI DER, algorithm parameters,
key bytes, signatures, extension/qualifier DER, opaque name contents and SCT
encodings. These fields have a `_base64` suffix (for example `der_base64` and
`value_der_base64`); arrays of encoded values use `values_der_base64`.
DN text stays in `value`, with original octets in `value_raw_base64`.

Fingerprints, serial numbers, key/log identifiers, integer content, encoded
flag octets and public-key components retain lowercase hex with a `_hex` suffix. Numeric lists
such as TLS feature numbers remain arrays of numbers. CBOR and MessagePack use native byte strings
for the raw blocks, with no `_base64` suffix; identifiers and numeric fields use the
same presentation as the text formats. No byte arrays are guessed from numeric lists.

FIDO AAGUID details use `{"kind":"fido_aaguid","value":{"uuid":"08987058-cadc-4b81-b6e1-30de50dcbe96"}}`.
Formatting preserves UUID byte order and does not enforce version, variant or
nonzero values. If the length is not 16 bytes, `value` contains `uuid: null`,
`raw_base64` (CBOR/MessagePack: `raw` bytes), and an `invalid_length` format diagnostic.
This is a display limitation and does not reject the certificate. Windows GUID
mixed-endian interpretation is not applied to FIDO AAGUIDs.

Version 2 changes only the CLI report representation; the library's Serde model
and summary schema remain unchanged. CLI consumers should use `report_version`;
the nested `schema_version` identifies the source library summary before report
adaptation. Text renders all report fields for humans. TOML omits null object
fields, converts unsigned integers above i64::MAX to decimal strings, and rejects null array elements rather than losing positions.
These are explicit TOML representation differences, not certificate data changes.
SCT timestamps remain milliseconds; certificate/private-key timestamps are seconds.
DER/PEM output preserves the original DER, including its signature, rather than
reconstructing a certificate from a report. Reports cannot be imported as certificates.


Generate a self-contained schema with `--schema` or `--schema --summary`.
See [the schema contract](SCHEMA.md) for automatic generation, versioning,
format differences and validation commands.
