# sanitization 2.1.0

This release adds an isolated compatibility path for projects migrating from
`secrecy` 0.10 while preserving the stricter exposure and storage contracts of
the native `sanitization` containers.

## Secrecy compatibility companion

- Add the `sanitization-secrecy` sister crate with `SecretBox<S>`,
  `SecretSlice<S>`, `SecretString`, `ExposeSecret`, and `ExposeSecretMut`.
- Add explicit `CloneableSecret` support and optional plaintext Serde through
  `SerializableSecret`.
- Bound `SecretString` Serde loading to 1 MiB by default and isolate generic,
  inherently unbounded `SecretBox<T>` loading behind the explicit
  `serde-compat-unbounded` feature.
- Provide the familiar `new`, `init_with_mut`, `init_with`, and
  `try_init_with` constructors. Temporary values used by cloning constructors
  are protected by a sanitizing unwind guard, and clone-based constructors
  require the explicit `CloneableSecret` partial-destination cleanup contract.
- Add `try_init_with_mut`, runtime-length final-allocation byte-slice
  initialization, exact-capacity no-copy vector transfer, and data-oblivious
  equality with explicit call-site declassification.
- Require audited shared and mutable storage-stability contracts for
  `SecretBox` reference exposure and mutable initialization under every feature
  combination. The explicit `hazmat-unrestricted-exposure` feature adds a
  visibly distinct `UnrestrictedSecretBox` rather than weakening existing
  trait implementations through Cargo feature unification.
- Make runtime-length byte-slice allocation genuinely fallible and add
  `try_init_with_len_bounded::<MAX, _>` so untrusted lengths are rejected
  before allocation or initialization with typed build/initializer errors.
- Clear complete owned `String` and `Vec` source capacities during boxed
  conversion, and sanitize completed destination elements if a later slice
  clone unwinds.
- Build cloned slices directly in exact boxed storage with initialized-prefix
  unwind cleanup and a mandatory full-initialization assertion before the guard
  is disarmed, avoiding allocator-dependent `Vec` capacity assertions, and
  restrict automatic array clone authorization to reviewed integer arrays.
- Make explicit consumption sanitize exactly once and add diagnostic-matching
  regression coverage for the clone authorization marker.
- Correct full-capacity `String` wiping to use allocation-wide vector
  provenance, preserving UTF-8 validity during optional multi-pass clearing
  and covering excess-capacity strings under Miri.
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
exposure. `SecretString` remains unconditionally cloneable for upstream source
compatibility; other custom cloneable values must implement both
`SecureSanitize` and `CloneableSecret`.

All six workspace crates are coordinated at version `2.1.0`. The runtime keeps
an exact dependency on the matching derive crate, and companions retain caret
requirements on the core runtime.
