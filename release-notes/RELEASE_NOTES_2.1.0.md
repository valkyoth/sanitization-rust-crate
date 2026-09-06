# sanitization 2.1.0

This release adds an isolated compatibility path for projects migrating from
`secrecy` 0.10 while preserving the stricter exposure and storage contracts of
the native `sanitization` containers.

## Secrecy compatibility companion

- Add the `sanitization-secrecy` sister crate with `SecretBox<S>`,
  `SecretSlice<S>`, `SecretString`, `ExposeSecret`, and `ExposeSecretMut`.
- Add explicit `CloneableSecret` support and optional plaintext Serde through
  `SerializableSecret`.
- Provide the familiar `new`, `init_with_mut`, `init_with`, and
  `try_init_with` constructors. Temporary values used by cloning constructors
  are protected by a sanitizing unwind guard.
- Re-export `zeroize` by default and implement `Zeroize`/`ZeroizeOnDrop` for
  the compatibility wrapper by delegating to `SecureSanitize`.
- Support Cargo package aliasing so many existing `secrecy::...` imports can
  remain unchanged during incremental migration.
- Add downstream package-alias tests, no-default/all-feature tests, Miri
  coverage, package verification, and release-script integration.

## Core support

- Add `SecureSanitize` for `str`, routing its single unsafe byte-view
  conversion through the existing audited wipe backend. Replacing every byte
  with ASCII NUL preserves UTF-8 validity and enables fixed boxed strings to be
  cleared without allocation.

## Security scope

The compatibility wrappers intentionally do not add reference-returning
exposure, cloning, or plaintext serialization to native hardened containers.
They provide baseline boxed ownership and clear-on-drop behavior, not memory
locking, guard pages, canaries, storage-history recovery, or closure-confined
exposure. Custom types must implement `SecureSanitize`.

All six workspace crates are coordinated at version `2.1.0`. The runtime keeps
an exact dependency on the matching derive crate, and companions retain caret
requirements on the core runtime.
