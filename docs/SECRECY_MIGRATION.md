# Migrating From `secrecy` 0.10

`sanitization-secrecy` provides a source-compatible subset of the familiar
`secrecy` 0.10 API while routing final owned-value cleanup through
`sanitization::SecureSanitize`.

## Release Objective

The 2.1.0 objective is deliberately finite: existing applications can alias
this package as `secrecy`, retain the boxed-secret types and exposure traits
listed below, and move cleanup ownership to `sanitization` without adding
reference-returning APIs to the hardened core containers.

This objective is complete when the compatibility surface:

- builds with and without its default `zeroize` bridge;
- supports the documented optional Serde behavior;
- clears the current boxed value on explicit clearing, unwinding, and drop;
- is exercised through a downstream Cargo package alias; and
- participates in workspace checks, Miri, archive verification, and release
  ordering.

It is not a goal to reproduce undocumented internals, support every historical
`secrecy` release, accept custom types that only implement `Zeroize`, or add
memory locking and scoped exposure to this compatibility wrapper. Those uses
belong to native `sanitization` containers or a separately scoped future
change.

## Cargo Alias

Existing `secrecy::...` imports can remain unchanged by aliasing the package:

```toml
[dependencies]
secrecy = { package = "sanitization-secrecy", version = "2.1.0" }
```

Enable plaintext serialization only where it is an explicit protocol
requirement:

```toml
[dependencies]
secrecy = {
    package = "sanitization-secrecy",
    version = "2.1.0",
    features = ["serde"],
}
```

## Supported API

| `secrecy` 0.10 API | Compatibility status |
| --- | --- |
| `SecretBox<S>` | Supported with a `SecureSanitize` bound |
| `SecretSlice<S>` | Supported |
| `SecretString` | Supported |
| `ExposeSecret` | Supported |
| `ExposeSecretMut` | Supported |
| `CloneableSecret` | Supported with a `SecureSanitize` bound |
| `SerializableSecret` | Supported behind `serde` |
| `new`, `init_with_mut`, `init_with`, `try_init_with` | Supported |
| `secrecy::zeroize` re-export | Supported by the default `zeroize-interop` feature |
| `Zeroize` and `ZeroizeOnDrop` for `SecretBox` | Supported by `zeroize-interop`; delegates to `SecureSanitize` |

## Required Source Changes

The generic value bound changes from `zeroize::Zeroize` to
`sanitization::SecureSanitize`. Primitive values, arrays, slices, `String`,
`Vec`, and other built-in sanitizable values work directly. Custom types that
only implement `Zeroize` must derive or manually implement `SecureSanitize`.

Enable the derive macro when using the derived form shown below:

```toml
[dependencies]
sanitization = { version = "2.1.0", features = ["derive"] }
secrecy = { package = "sanitization-secrecy", version = "2.1.0" }
```

```rust
use sanitization::SecureSanitize;
use secrecy::{ExposeSecret, SecretBox};

#[derive(SecureSanitize)]
struct Credentials {
    token: [u8; 32],
}

let secret = SecretBox::new(Box::new(Credentials { token: [7; 32] }));
let credentials = secret.expose_secret();
let first = credentials.token[0];
# let _ = first;
```

`ExposeSecret::expose_secret` returns an ordinary reference rather than
running a closure. Existing closure-based calls must therefore be changed to a
borrow, while code that already used the `secrecy` trait shape remains the
same.

## Security Classification

The compatibility wrapper guarantees redacted `Debug` and sanitization of its
currently boxed value on explicit clearing and drop. It does not guarantee:

- closure-confined exposure;
- wipe-before-growth for mutations performed through `ExposeSecretMut`;
- cleanup of allocations released before the value entered its final box;
- memory locking, dump/fork exclusion, canaries, guard pages, or page sealing;
- cleanup of clones or serialized plaintext after they leave the wrapper.

`init_with_mut` initializes the final boxed allocation and is preferred.
`init_with` and `try_init_with` necessarily clone a temporary, but the
temporary is held in a sanitizing unwind guard in this implementation.

For new code, prefer native `sanitization` containers. Use this companion when
incremental source migration or an existing `ExposeSecret` trait bound is the
primary requirement.
