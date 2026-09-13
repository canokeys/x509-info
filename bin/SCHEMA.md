# CLI report schema

The CLI emits report version 2. Generate its JSON Schema Draft 2020-12 contract
without reading a certificate:

```sh
x509-info --schema --output report.schema.json
x509-info --schema --summary --output summary.schema.json
```

From this repository, prefix the arguments with
`cargo run -p x509-info --features cli --locked --`. Both schemas are self-contained:
all references resolve within `$defs`; generating or validating them needs no
network access. Their identifiers are `urn:x509-info:report:2:full` and
`urn:x509-info:report:2:summary`.

## Generation and scope

Schemars derives the source schemas from the Rust serialization types, including
all extension and GeneralName variants, optional values, diagnostics and nested
fields. The CLI applies the same field mapping used by its report encoder for
Base64, hex, UUID display and name enrichment. It does not infer schemas from
example certificates. Report envelopes and diagnostic records are typed Rust
structures as well, so adding fields updates the generated schema.

The library's optional `schema` feature implements `schemars::JsonSchema` for its
Serde result types. That describes the library's original serialization, including
byte arrays and raw hex fields. Use CLI `--schema` to describe CLI exports after
presentation adaptation. Neither schema performs certificate validity or trust
checks.

## Format contracts

| Format | Contract |
| --- | --- |
| JSON | Full or summary schema, according to `--summary` |
| JSON Lines (`jsonl`) | One JSON report per invocation, on one line with a trailing newline; the same schema |
| YAML | Same strings, numbers, nulls, arrays and maps as JSON; validate after YAML decoding |
| TOML | Same field names; absent/null object fields are omitted, and integers above i64::MAX become decimal strings. The JSON Schema is not directly applicable without restoring those representations |
| CBOR / MessagePack | Same report structure with native byte strings for raw blocks and no `_base64` suffix on those fields; hex identifiers and UUID strings remain text |
| Text | Human-readable rendering of the textual report, not a machine interchange schema |
| DER / PEM | Original certificate encoding, outside the report schema |

Each invocation reads exactly one certificate. JSON Lines output can be appended to
a log, but does not enable certificate-bundle input. MessagePack uses maps with named
fields and native binary values; `msgpack` is an alias for `messagepack`.

## Versioning and verification

`report_version` owns the CLI contract. The nested summary `schema_version` records
the source library summary version before CLI adaptation. Consumers should choose
the full/summary schema matching the command that produced a report, tolerate
additional fields, and handle unfamiliar enum kinds when upgrading. Incompatible
field or encoding changes require a new report version; additive schema coverage
and new output formats do not.

Generated schemas describe known variants for the current build. They do not
replace raw unknown-OID handling: a certificate extension without a decoder is
still represented by the existing `unsupported` variant.

CI generates both schemas, checks the schemas themselves, validates every PEM
fixture's full and summary JSON exports, checks malformed report rejection, and
compares decoded YAML/JSON Lines against JSON using independent implementations:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-schema.txt
cargo build -p x509-info --features cli --locked
.venv/bin/python scripts/check-x509-schema.py target/debug/x509-info
```

Schema files are generated on demand, avoiding a second handwritten or stale copy
of the contract. Keep an exported schema with reports when long-term reproducibility
requires the exact producing build's definitions.
