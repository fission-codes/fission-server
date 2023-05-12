//! Authority key material constants and functions

use ed25519_zebra::{SigningKey as Ed25519PrivateKey, VerificationKey as Ed25519PublicKey};
use ucan::crypto::did::KeyConstructorSlice;

use ucan_key_support::{
    ed25519::{bytes_to_ed25519_key, Ed25519KeyMaterial, ED25519_MAGIC_BYTES},
    p256::{bytes_to_p256_key, P256_MAGIC_BYTES},
    rsa::{bytes_to_rsa_key, RSA_MAGIC_BYTES},
};

///////////////
// CONSTANTS //
///////////////

/// DID of the fission-server
pub const SERVER_DID: &str =
    "did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4";

/// Supported key types by the various Fission services
pub const SUPPORTED_KEYS: &KeyConstructorSlice = &[
    (ED25519_MAGIC_BYTES, bytes_to_ed25519_key),
    (P256_MAGIC_BYTES, bytes_to_p256_key),
    (RSA_MAGIC_BYTES, bytes_to_rsa_key),
];

/////////////
// ED25519 //
/////////////

pub fn generate_ed25519_material() -> Ed25519KeyMaterial {
    let private_key = Ed25519PrivateKey::new(rand::thread_rng());
    let public_key = Ed25519PublicKey::from(&private_key);
    Ed25519KeyMaterial(public_key, Some(private_key))
}
