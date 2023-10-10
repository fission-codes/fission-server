//! A simple wrapper around an EdDSA Ed25519 signing key that provides zeroization & a `did:key:` representation

use did_key::{Ed25519KeyPair, Fingerprint};
use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::thread_rng;
use signature::Signer;
use zeroize::ZeroizeOnDrop;

/// An Ed25519 EdDSA `did:key:zM...` with the signing key stored in-memory and zeroized on drop
#[derive(ZeroizeOnDrop)]
pub struct EdDidKey {
    signing_key: SigningKey,
    #[zeroize(skip)]
    did_key_string: String,
}

impl std::fmt::Debug for EdDidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EdDidKey")
            .field(&self.did_key_string)
            .finish()
    }
}

impl EdDidKey {
    /// Wrap an existing Ed25519 signing key
    pub fn new(signing_key: SigningKey) -> Self {
        let did_key_string = did_key_str(&signing_key.verifying_key());
        Self {
            signing_key,
            did_key_string,
        }
    }

    /// Generate a new keypair from thread randomness
    pub fn generate() -> Self {
        Self::new(SigningKey::generate(&mut thread_rng()))
    }
}

impl Signer<Signature> for EdDidKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.signing_key.try_sign(msg)
    }
}

impl AsRef<str> for EdDidKey {
    fn as_ref(&self) -> &str {
        &self.did_key_string
    }
}

fn did_key_str(key: &VerifyingKey) -> String {
    format!(
        "did:key:{}",
        Ed25519KeyPair::from_public_key(key.as_bytes()).fingerprint()
    )
}
