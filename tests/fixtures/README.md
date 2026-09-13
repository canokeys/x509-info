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
