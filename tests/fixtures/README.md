# Certificate fixture

`inspection.pem` is a synthetic self-signed P-256 certificate generated locally
with OpenSSL for parser tests. It has serial 42, O=canokeys.org,
CN=libcanokey test certificate, CA:FALSE and DNS:example.invalid.
It is not a trust anchor or a real device identity. The temporary private key
was discarded and is not required to execute tests. Tests use explicit encoded
timestamps, not the system clock. No upstream/user certificate was copied.

`p521.pem` (serial 43) checks that the nominal P-521 size is 521, not the
rounded coordinate encoding width of 528. `rsa2048.pem` (serial 44) checks
that DER INTEGER sign padding is excluded from RSA modulus size. Both were
generated the same way with their respective key algorithms; their temporary
private keys were also discarded.

`details.pem` (serial 45) is a locally generated synthetic P-256 certificate with
fixed 2025-2030 validity, a multi-valued RDN, repeated OU attributes, UTF-8 text,
an unknown name attribute, DNS/email/IPv4/IPv6/URI SANs, KU, client-auth plus unknown
EKU, and an unknown critical extension. `ed25519.pem` (46) and `ed448.pem` (47)
use the same fields with their respective key/signature algorithms. They were
generated with Python cryptography; private keys were never saved.

`pss.pem` (48) was generated with OpenSSL RSA-PSS, a 2048-bit key, SHA-256,
MGF1-SHA256 and salt length 32, used for both restricted SPKI and signature
parameters. Its temporary private key was removed. Signatures on mutated test
certificates are intentionally invalid; inspection does not verify them.

`details.sha256` was computed independently with Python hashlib over the fixture
DER. `details.json` is a reviewed schema-v1 summary snapshot, checked alongside
explicit field assertions. No fixture requires network, randomness or OpenSSL
at test runtime. Regenerating random keys changes fingerprints and the snapshot.
