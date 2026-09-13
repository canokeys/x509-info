# x509-info

Owned X.509 certificate information for applications, independent of CanoKey,
transport, bindings and runtime state. Callers own inputs and results.

```rust
use x509_info::{parse_der, ParseOptions};
# fn inspect(der: &[u8]) -> Result<(), x509_info::Error> {
let info = parse_der(der, ParseOptions::default())?;
println!("{}", info.subject.display);
# Ok(())
# }
```

The crate uses x509-parser and pem-rfc7468 for format parsing. It does not verify
signatures, certificate chains, trust or revocation. Time checks require an
explicit caller timestamp. Enable `serde` for owned result serialization.

Rust 1.85 or later is required. Native and wasm32-unknown-unknown are supported.
This experimental package remains unpublished while its application model evolves.
It can be used directly or through the optional `canokey::x509` re-export.

Original code is Apache-2.0, authored by canokeys.org. The packaged LICENSE covers
original code; LICENSE.console retains the MIT notice for adapted Console code.
