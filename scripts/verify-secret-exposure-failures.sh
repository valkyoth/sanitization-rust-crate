#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_expected_failure() {
    name="$1"
    features="$2"
    needle="$3"
    source="$4"
    secrecy_features="${5:-}"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
sanitization = { path = "${root}/crates/sanitization", features = [${features}] }
sanitization-secrecy = { path = "${root}/crates/sanitization-secrecy", default-features = false, features = [${secrecy_features}] }
EOF

    printf '%s\n' "${source}" >"${case_dir}/src/lib.rs"

    log="${case_dir}/cargo-check.log"
    if cargo check --manifest-path "${case_dir}/Cargo.toml" >"${log}" 2>&1; then
        printf 'expected %s to fail, but it compiled\n' "${name}" >&2
        exit 1
    fi

    if ! grep -Fq "${needle}" "${log}"; then
        printf 'expected %s failure to mention:\n%s\n\nactual output:\n' \
            "${name}" "${needle}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_secrecy_serde_expected_failure() {
    name="secrecy-generic-serde-without-unbounded-opt-in-rejected"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
sanitization-secrecy = { path = "${root}/crates/sanitization-secrecy", default-features = false, features = ["serde"] }
serde_json = "1"
EOF

    cat >"${case_dir}/src/lib.rs" <<'EOF'
use sanitization_secrecy::SecretBox;

pub fn deserialize_generic_secret(json: &str) {
    let _: SecretBox<String> = serde_json::from_str(json).unwrap();
}
EOF

    log="${case_dir}/cargo-check.log"
    if cargo check --manifest-path "${case_dir}/Cargo.toml" >"${log}" 2>&1; then
        printf 'expected %s to fail, but it compiled\n' "${name}" >&2
        exit 1
    fi

    if ! grep -Fq 'SecretBox<std::string::String>: serde::Deserialize' "${log}"; then
        printf 'expected %s to reject generic serde without serde-compat-unbounded\n\nactual output:\n' \
            "${name}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_expected_failure \
    "secret-vec-shared-exposure-rejected" \
    '"alloc"' \
    '`Vec<u8>: StableSharedSecretStorage`' \
    'use sanitization::Secret;

pub fn expose() {
    let secret = Secret::new(vec![1_u8, 2, 3, 4]);
    secret.with_secret(|bytes| bytes.len());
}'

run_expected_failure \
    "secret-string-mutable-exposure-rejected" \
    '"alloc"' \
    '`String: StableMutableSecretStorage`' \
    'use sanitization::Secret;

pub fn expose() {
    let mut secret = Secret::new(String::from("secret"));
    secret.with_secret_mut(|text| text.push_str("-rotated"));
}'

run_expected_failure \
    "secret-interior-mutable-exposure-rejected" \
    '"std"' \
    '`Rotating: StableSharedSecretStorage`' \
    'use std::cell::RefCell;
use sanitization::{Secret, SecureSanitize};

struct Rotating {
    bytes: RefCell<Vec<u8>>,
}

impl SecureSanitize for Rotating {
    fn secure_sanitize(&mut self) {
        self.bytes.get_mut().secure_sanitize();
    }
}

pub fn expose() {
    let secret = Secret::new(Rotating {
        bytes: RefCell::new(vec![1, 2, 3, 4]),
    });
    secret.with_secret(|value| {
        value.bytes.replace(vec![9, 9, 9, 9]);
    });
}'

run_expected_failure \
    "custom-wipe-implementation-rejected" \
    '"alloc"' \
    'sealed trait' \
    'use sanitization::wipe::Wipe;

pub struct NoOpWipe([u8; 4]);

impl Wipe for NoOpWipe {
    fn wipe(&mut self) {}
}'

run_expected_failure \
    "secrecy-clone-without-marker-rejected" \
    '"alloc"' \
    '`RequiresOptIn: CloneableSecret`' \
    'use sanitization::SecureSanitize;
use sanitization_secrecy::SecretBox;

#[derive(Clone)]
struct RequiresOptIn(u8);

impl SecureSanitize for RequiresOptIn {
    fn secure_sanitize(&mut self) {
        self.0.secure_sanitize();
    }
}

pub fn duplicate() {
    let secret = SecretBox::new(Box::new(RequiresOptIn(7)));
    let _duplicate = secret.clone();
}'

run_expected_failure \
    "secrecy-cloning-constructor-without-marker-rejected" \
    '"alloc"' \
    '`RequiresOptIn: CloneableSecret`' \
    'use sanitization::SecureSanitize;
use sanitization_secrecy::SecretBox;

#[derive(Clone)]
struct RequiresOptIn(u8);

impl SecureSanitize for RequiresOptIn {
    fn secure_sanitize(&mut self) {
        self.0.secure_sanitize();
    }
}

pub fn construct() {
    let _secret = SecretBox::init_with(|| RequiresOptIn(7));
}'

run_expected_failure \
    "secrecy-unstable-shared-exposure-rejected" \
    '"alloc"' \
    'StableSharedSecretStorage' \
    'use sanitization_secrecy::{ExposeSecret, SecretBox};

pub fn expose_unstable_storage() {
    let secret = SecretBox::new(Box::new(String::from("token")));
    let _ = secret.expose_secret();
}' \
    '"hazmat-unrestricted-exposure"'

run_expected_failure \
    "secrecy-unstable-mutable-initialization-rejected" \
    '"alloc"' \
    'StableMutableSecretStorage' \
    'use sanitization_secrecy::SecretBox;

pub fn initialize_unstable_storage() {
    let _ = SecretBox::<String>::init_with_mut(|text| text.push_str("token"));
}' \
    '"hazmat-unrestricted-exposure"'

run_expected_failure \
    "secrecy-custom-copy-array-clone-rejected" \
    '"alloc"' \
    '`[CustomCopy; 4]: CloneableSecret`' \
    'use sanitization::SecureSanitize;
use sanitization_secrecy::{CloneableSecret, SecretBox};

#[derive(Clone, Copy)]
struct CustomCopy(u8);

impl SecureSanitize for CustomCopy {
    fn secure_sanitize(&mut self) {
        self.0.secure_sanitize();
    }
}

impl CloneableSecret for CustomCopy {}

pub fn duplicate_array() {
    let secret = SecretBox::new(Box::new([CustomCopy(7); 4]));
    let _duplicate = secret.clone();
}'

run_secrecy_serde_expected_failure

run_expected_failure \
    "allowlisted-secret-unapproved-type-rejected" \
    '"std"' \
    '`DeploymentPolicy: SecretStoragePolicy<SecretBytes<16>>`' \
    'use sanitization::{
    define_secret_storage_policy, AllowlistedSecret, SecretBytes,
};

define_secret_storage_policy! {
    DeploymentPolicy {
        SecretBytes<32> => "reviewed fixed key storage",
    }
}

pub fn construct() {
    let _ = AllowlistedSecret::<SecretBytes<16>, DeploymentPolicy>::new(
        SecretBytes::from_array([0; 16]),
    );
}'

run_expected_failure \
    "storage-policy-empty-rationale-rejected" \
    '"std"' \
    'secret storage policy rationale must not be empty or ASCII-whitespace-only' \
    'use sanitization::{define_secret_storage_policy, SecretBytes};

define_secret_storage_policy! {
    DeploymentPolicy {
        SecretBytes<32> => "",
    }
}'

run_expected_failure \
    "storage-policy-whitespace-rationale-rejected" \
    '"std"' \
    'secret storage policy rationale must not be empty or ASCII-whitespace-only' \
    'use sanitization::{define_secret_storage_policy, SecretBytes};

define_secret_storage_policy! {
    DeploymentPolicy {
        SecretBytes<32> => "  \t\n  ",
    }
}'

printf 'generic secret exposure failure checks passed\n'
