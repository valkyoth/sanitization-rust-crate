<p align="center">
  <b>Secrecy-style compatibility wrappers backed by sanitization.</b><br>
  Familiar boxed-secret APIs for incremental migration without weakening the hardened core.
</p>

<div align="center">
  <a href="https://crates.io/crates/sanitization">sanitization crate</a>
  |
  <a href="https://docs.rs/sanitization-secrecy">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/docs/SAFETY.md">Safety</a>
  |
  <a href="https://github.com/valkyoth/sanitization/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/sanitization">
    <img src="https://raw.githubusercontent.com/valkyoth/sanitization/main/.github/images/sanitization.webp" alt="sanitization Rust crate overview">
  </a>
</p>

# sanitization-secrecy

`sanitization-secrecy` provides a migration-compatible subset of the familiar
`secrecy` 0.10 API while delegating owned-value clearing to
[`sanitization`](https://crates.io/crates/sanitization).

```toml
[dependencies]
sanitization-secrecy = "2.1.0"
```

Applications can preserve `secrecy::...` import paths with a Cargo package
alias:

```toml
[dependencies]
secrecy = { package = "sanitization-secrecy", version = "2.1.0" }
```

```rust
use secrecy::{ExposeSecret, SecretString};

let token = SecretString::from("bearer-token");
assert_eq!(token.expose_secret(), "bearer-token");
```

## Supported surface

- `SecretBox<S>`
- `SecretSlice<S>` and `SecretString`
- `ExposeSecret` and `ExposeSecretMut`
- `CloneableSecret`
- `SerializableSecret` behind `serde`
- the `secrecy::zeroize` re-export and `Zeroize`/`ZeroizeOnDrop` wrapper
  implementations through the default `zeroize-interop` feature
- `new`, `init_with_mut`, `init_with`, and `try_init_with`
- redacted `Debug` and sanitization on drop

The generic bound is `sanitization::SecureSanitize`, not
`zeroize::Zeroize`. Custom migrated types must derive or implement
`SecureSanitize`.

## Security boundary

This is intentionally a compatibility API. Returning `&S` or `&mut S` permits
the caller to retain a borrow for its full Rust lifetime and to invoke methods
that may copy, replace, or reallocate secret storage. Cloning creates another
secret copy. Implementing `SerializableSecret` explicitly permits plaintext
serialization and places serializer buffers outside this crate's clearing
guarantee.

For new high-assurance code, prefer the native `sanitization` containers. They
provide scoped exposure, fixed and bounded storage, wipe-before-growth,
memory-locking policy, canaries, guard pages, and structured protection
reporting that this compatibility wrapper does not claim.
