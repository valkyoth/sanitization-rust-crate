# sanitization 2.0.4

This maintenance release updates the supported toolchain and dependency set
without changing the public API or the Rust `1.90.0` MSRV.

## Maintenance updates

- Release development is pinned to Rust `1.98.1`, and the compatibility matrix
  now checks Rust `1.90.0` through `1.98.1`.
- `syn` is updated to `3.0.4` and BLAKE3 to `1.8.7`; compatible transitive
  dependencies and standalone-tool lockfiles are refreshed.
- The SHA-pinned `Swatinem/rust-cache` action is updated to `2.9.2`. The
  repository's checkout, artifact upload, and Kani action pins were reviewed
  and remain current.
- The performance baseline keeps detailed measurements in its structured JSON
  artifact but no longer prints the complete report to CI logs. Console output
  now contains only a fixed pass/fail status, resolving the CodeQL
  cleartext-logging alert without reducing retained benchmark evidence.

All five workspace crates are released together at `2.0.4`, with the derive
crate exact-pinned to the matching runtime version.
