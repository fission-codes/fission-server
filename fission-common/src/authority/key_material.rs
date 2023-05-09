use ucan::crypto::did::KeyConstructorSlice;

use ucan_key_support::{
    ed25519::{bytes_to_ed25519_key, ED25519_MAGIC_BYTES},
    p256::{bytes_to_p256_key, P256_MAGIC_BYTES},
    rsa::{bytes_to_rsa_key, RSA_MAGIC_BYTES},
};

// SUPPORTED KEYS
// --------------

pub const SUPPORTED_KEYS: &KeyConstructorSlice = &[
    (ED25519_MAGIC_BYTES, bytes_to_ed25519_key),
    (P256_MAGIC_BYTES, bytes_to_p256_key),
    (RSA_MAGIC_BYTES, bytes_to_rsa_key),
];
