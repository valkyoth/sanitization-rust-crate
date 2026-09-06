#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! Compatibility-oriented secret wrappers backed by [`sanitization`].
//!
//! This crate provides the familiar `SecretBox`, `SecretSlice`,
//! `SecretString`, `ExposeSecret`, and `ExposeSecretMut` API shape for projects
//! migrating from `secrecy` 0.10. It deliberately keeps reference-returning
//! exposure, cloning, and plaintext serialization out of the hardened
//! `sanitization` containers.
//!
//! The compatibility wrapper provides redacted formatting and sanitizes its
//! currently boxed value on drop. It does not provide memory locking, guard
//! pages, storage-history recovery, or the scoped-exposure guarantees of the
//! native `sanitization` container families.

extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{any, fmt};
use sanitization::SecureSanitize;

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

/// The `zeroize` API used by `secrecy` callers, available through the default
/// `zeroize-interop` compatibility feature.
#[cfg(feature = "zeroize-interop")]
pub use zeroize;

/// A boxed secret value with explicit reference exposure and clearing on drop.
///
/// This compatibility type intentionally exposes references through
/// [`ExposeSecret`] and [`ExposeSecretMut`]. Prefer native `sanitization`
/// containers when scoped closure exposure, stable-storage contracts, memory
/// locking, canaries, or guard pages are required.
pub struct SecretBox<S: SecureSanitize + ?Sized> {
    inner_secret: Box<S>,
}

impl<S: SecureSanitize + ?Sized> SecretBox<S> {
    /// Wrap an already boxed secret without copying it.
    #[must_use]
    #[inline]
    pub const fn new(boxed_secret: Box<S>) -> Self {
        Self {
            inner_secret: boxed_secret,
        }
    }

    /// Sanitize the currently boxed value while retaining its allocation.
    #[inline]
    pub fn clear_secret(&mut self) {
        self.inner_secret.secure_sanitize();
    }

    /// Consume this wrapper after sanitizing its value.
    #[inline]
    pub fn into_cleared(mut self) {
        self.clear_secret();
    }
}

impl<S: SecureSanitize + Default> SecretBox<S> {
    /// Allocate a default value and initialize it directly through a mutable
    /// reference.
    ///
    /// If `initialize` panics, the partially initialized boxed value is
    /// sanitized during unwinding.
    #[must_use]
    #[inline]
    pub fn init_with_mut(initialize: impl FnOnce(&mut S)) -> Self {
        let mut secret = Self::default();
        initialize(secret.expose_secret_mut());
        secret
    }
}

impl<S: SecureSanitize + Clone> SecretBox<S> {
    /// Construct a value, clone it into its final allocation, and sanitize the
    /// temporary value.
    ///
    /// Prefer [`SecretBox::new`] or [`SecretBox::init_with_mut`] because this
    /// operation necessarily creates a temporary copy. The temporary is also
    /// sanitized if cloning panics and Rust unwinds. Cleanup is not guaranteed
    /// after an abort, including an allocation failure handled by aborting.
    #[must_use]
    #[inline]
    pub fn init_with(construct: impl FnOnce() -> S) -> Self {
        let temporary = TemporarySecret::new(construct());
        Self::new(Box::new(temporary.value().clone()))
    }

    /// Fallible form of [`SecretBox::init_with`].
    ///
    /// Generator errors are returned directly. A successfully generated
    /// temporary is sanitized on success and during panic unwinding.
    #[inline]
    pub fn try_init_with<E>(construct: impl FnOnce() -> Result<S, E>) -> Result<Self, E> {
        let temporary = TemporarySecret::new(construct()?);
        Ok(Self::new(Box::new(temporary.value().clone())))
    }
}

impl<S: SecureSanitize + ?Sized> From<Box<S>> for SecretBox<S> {
    #[inline]
    fn from(source: Box<S>) -> Self {
        Self::new(source)
    }
}

impl<S: SecureSanitize + Default> Default for SecretBox<S> {
    #[inline]
    fn default() -> Self {
        Self::new(Box::<S>::default())
    }
}

impl<S: SecureSanitize + ?Sized> SecureSanitize for SecretBox<S> {
    #[inline]
    fn secure_sanitize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "zeroize-interop")]
impl<S: SecureSanitize + ?Sized> zeroize::Zeroize for SecretBox<S> {
    #[inline]
    fn zeroize(&mut self) {
        self.clear_secret();
    }
}

#[cfg(feature = "zeroize-interop")]
impl<S: SecureSanitize + ?Sized> zeroize::ZeroizeOnDrop for SecretBox<S> {}

impl<S: SecureSanitize + ?Sized> Drop for SecretBox<S> {
    #[inline]
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl<S: SecureSanitize + ?Sized> fmt::Debug for SecretBox<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SecretBox<{}>([REDACTED])",
            any::type_name::<S>()
        )
    }
}

impl<S: CloneableSecret> Clone for SecretBox<S> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.inner_secret.clone())
    }
}

impl<S: SecureSanitize + ?Sized> ExposeSecret<S> for SecretBox<S> {
    #[inline]
    fn expose_secret(&self) -> &S {
        self.inner_secret.as_ref()
    }
}

impl<S: SecureSanitize + ?Sized> ExposeSecretMut<S> for SecretBox<S> {
    #[inline]
    fn expose_secret_mut(&mut self) -> &mut S {
        self.inner_secret.as_mut()
    }
}

/// A boxed secret slice.
pub type SecretSlice<S> = SecretBox<[S]>;

impl<S: SecureSanitize> From<Vec<S>> for SecretSlice<S> {
    /// Convert using the standard library's boxed-slice conversion.
    ///
    /// The standard library may discard excess vector capacity. This wrapper
    /// cannot sanitize an allocation after that conversion has released it.
    /// Prefer [`SecretBox::new`] with an already boxed slice or a native
    /// `sanitization` container when allocation history is in scope.
    #[inline]
    fn from(source: Vec<S>) -> Self {
        Self::from(source.into_boxed_slice())
    }
}

impl<S: CloneableSecret> Clone for SecretSlice<S> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.inner_secret.clone())
    }
}

impl<S: SecureSanitize> Default for SecretSlice<S> {
    #[inline]
    fn default() -> Self {
        Vec::new().into()
    }
}

/// A boxed UTF-8 secret string.
pub type SecretString = SecretBox<str>;

impl From<String> for SecretString {
    /// Convert using the standard library's boxed-string conversion.
    ///
    /// The standard library may discard excess string capacity. This wrapper
    /// cannot sanitize an allocation after that conversion has released it.
    /// Prefer [`SecretBox::new`] with an already boxed `str` or a native
    /// `sanitization::SecretString` when allocation history is in scope.
    #[inline]
    fn from(source: String) -> Self {
        Self::from(source.into_boxed_str())
    }
}

impl From<&str> for SecretString {
    /// Copy a borrowed string into compatibility storage.
    ///
    /// The source remains outside this wrapper's ownership and clearing
    /// guarantee.
    #[inline]
    fn from(source: &str) -> Self {
        Self::from(String::from(source))
    }
}

impl Clone for SecretString {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.inner_secret.clone())
    }
}

impl Default for SecretString {
    #[inline]
    fn default() -> Self {
        String::new().into()
    }
}

/// Marker for secret values whose owners explicitly permit duplication.
///
/// Types do not become cloneable merely by implementing [`SecureSanitize`]:
///
/// ```compile_fail
/// use alloc::boxed::Box;
/// use sanitization::SecureSanitize;
/// use sanitization_secrecy::SecretBox;
///
/// struct NonCloneable(u8);
/// impl SecureSanitize for NonCloneable {
///     fn secure_sanitize(&mut self) {
///         self.0.secure_sanitize();
///     }
/// }
///
/// let secret = SecretBox::new(Box::new(NonCloneable(7)));
/// let duplicate = secret.clone();
/// # let _ = duplicate;
/// ```
pub trait CloneableSecret: Clone + SecureSanitize {}

macro_rules! impl_cloneable_secret {
    ($($type:ty),+ $(,)?) => {
        $(impl CloneableSecret for $type {})+
    };
}

impl_cloneable_secret!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize,);

/// Expose a shared reference to an inner secret.
///
/// The returned reference can remain live for the full borrow of `self`. This
/// is a compatibility boundary and is intentionally less restrictive than
/// native `sanitization` scoped exposure APIs.
pub trait ExposeSecret<S: ?Sized> {
    /// Borrow the secret value.
    fn expose_secret(&self) -> &S;
}

/// Expose a mutable reference to an inner secret.
///
/// Implementations can permit operations that copy, replace, or reallocate
/// secret storage. Callers are responsible for the complete behavior of code
/// invoked through the returned reference.
pub trait ExposeSecretMut<S: ?Sized> {
    /// Mutably borrow the secret value.
    fn expose_secret_mut(&mut self) -> &mut S;
}

/// Marker for secret values whose owners explicitly permit plaintext Serde
/// serialization.
///
/// Implementing this trait is an exfiltration decision. Serialized output and
/// serializer-owned intermediate buffers are outside this crate's clearing
/// guarantees.
///
/// Serialization is unavailable without an explicit implementation:
///
/// ```compile_fail
/// use sanitization_secrecy::SecretBox;
///
/// let secret = SecretBox::new(Box::new(String::from("token")));
/// let encoded = serde_json::to_string(&secret).unwrap();
/// # let _ = encoded;
/// ```
#[cfg(feature = "serde")]
pub trait SerializableSecret: Serialize {}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for SecretBox<T>
where
    T: SecureSanitize + Clone + de::DeserializeOwned + Sized,
{
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Self::try_init_with(|| T::deserialize(deserializer))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecretString {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for SecretBox<T>
where
    T: SecureSanitize + SerializableSecret + Serialize + Sized,
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.expose_secret().serialize(serializer)
    }
}

struct TemporarySecret<T: SecureSanitize>(T);

impl<T: SecureSanitize> TemporarySecret<T> {
    #[inline]
    const fn new(value: T) -> Self {
        Self(value)
    }

    #[inline]
    const fn value(&self) -> &T {
        &self.0
    }
}

impl<T: SecureSanitize> Drop for TemporarySecret<T> {
    #[inline]
    fn drop(&mut self) {
        self.0.secure_sanitize();
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::{format, panic, sync::Arc};

    static DEFAULT_VALUE_CLEARED: AtomicBool = AtomicBool::new(false);

    #[cfg(feature = "serde")]
    impl SerializableSecret for String {}

    #[test]
    fn string_and_slice_round_trip() {
        let mut text = SecretString::from(String::from("token"));
        assert_eq!(text.expose_secret(), "token");
        text.expose_secret_mut().make_ascii_uppercase();
        assert_eq!(text.expose_secret(), "TOKEN");
        text.clear_secret();
        assert_eq!(text.expose_secret().as_bytes(), &[0; 5]);

        let bytes = SecretSlice::from(vec![1_u8, 2, 3]);
        assert_eq!(bytes.expose_secret(), &[1, 2, 3]);
    }

    #[test]
    fn debug_is_redacted() {
        let secret = SecretString::from("do-not-print");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("do-not-print"));
    }

    #[test]
    fn init_with_mut_writes_final_allocation() {
        let secret = SecretBox::<[u8; 4]>::init_with_mut(|bytes| {
            bytes.copy_from_slice(b"test");
        });
        assert_eq!(secret.expose_secret(), b"test");
    }

    #[derive(Clone)]
    struct TrackedSecret {
        cleared: Arc<AtomicBool>,
        byte: u8,
    }

    impl SecureSanitize for TrackedSecret {
        fn secure_sanitize(&mut self) {
            self.byte = 0;
            self.cleared.store(true, Ordering::SeqCst);
        }
    }

    impl CloneableSecret for TrackedSecret {}

    #[derive(Default)]
    struct DefaultTrackedSecret(u8);

    impl SecureSanitize for DefaultTrackedSecret {
        fn secure_sanitize(&mut self) {
            self.0 = 0;
            DEFAULT_VALUE_CLEARED.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn drop_sanitizes_boxed_value() {
        let cleared = Arc::new(AtomicBool::new(false));
        let secret = SecretBox::new(Box::new(TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 42,
        }));

        drop(secret);
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn cloned_secret_is_independent() {
        let source = SecretBox::new(Box::new(7_u32));
        let mut duplicate = source.clone();
        *duplicate.expose_secret_mut() = 9;

        assert_eq!(*source.expose_secret(), 7);
        assert_eq!(*duplicate.expose_secret(), 9);
    }

    #[test]
    fn init_temporary_is_sanitized_on_success() {
        let cleared = Arc::new(AtomicBool::new(false));
        let secret = SecretBox::init_with(|| TrackedSecret {
            cleared: Arc::clone(&cleared),
            byte: 42,
        });

        assert!(cleared.load(Ordering::SeqCst));
        assert_eq!(secret.expose_secret().byte, 42);
    }

    #[test]
    fn init_temporary_is_sanitized_when_clone_panics() {
        #[derive(Default)]
        struct PanicClone {
            cleared: Arc<AtomicBool>,
        }

        impl Clone for PanicClone {
            fn clone(&self) -> Self {
                panic!("injected clone panic")
            }
        }

        impl SecureSanitize for PanicClone {
            fn secure_sanitize(&mut self) {
                self.cleared.store(true, Ordering::SeqCst);
            }
        }

        let cleared = Arc::new(AtomicBool::new(false));
        let result = panic::catch_unwind({
            let cleared = Arc::clone(&cleared);
            move || {
                let _ = SecretBox::init_with(|| PanicClone { cleared });
            }
        });

        assert!(result.is_err());
        assert!(cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn init_with_mut_sanitizes_partial_value_during_unwind() {
        DEFAULT_VALUE_CLEARED.store(false, Ordering::SeqCst);
        let result = panic::catch_unwind(|| {
            let _ = SecretBox::<DefaultTrackedSecret>::init_with_mut(|secret| {
                secret.0 = 42;
                panic!("injected initializer panic");
            });
        });

        assert!(result.is_err());
        assert!(DEFAULT_VALUE_CLEARED.load(Ordering::SeqCst));
    }

    #[test]
    fn fallible_constructor_preserves_generator_error() {
        let result = SecretBox::<[u8; 4]>::try_init_with(|| Err::<[u8; 4], _>("failure"));
        assert_eq!(result.unwrap_err(), "failure");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_plaintext_requires_explicit_marker() {
        let secret: SecretBox<String> = serde_json::from_str("\"token\"").unwrap();
        assert_eq!(secret.expose_secret(), "token");
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"token\"");
    }
}
