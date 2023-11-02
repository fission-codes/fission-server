//! A simple wrapper around an EdDSA Ed25519 signing key that provides zeroization & a `did:key:` representation

use did_key::{Ed25519KeyPair, Fingerprint};
use ed25519::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    Signature,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::thread_rng;
use rs_ucan::crypto::SignerDid;
use signature::Signer;
use std::fmt::Display;
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

impl Display for EdDidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.did_key_string)
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

    /// Returns the DID public key string. Does a clone.
    pub fn did(&self) -> String {
        self.did_key_string.clone()
    }

    /// Similarly to `Self::did()`, returns the DID public key string, but without cloning.
    pub fn as_str(&self) -> &str {
        &self.did_key_string
    }
}

impl Signer<Signature> for EdDidKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.signing_key.try_sign(msg)
    }
}

impl AsRef<str> for EdDidKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl DecodePrivateKey for EdDidKey {
    fn from_pkcs8_der(bytes: &[u8]) -> ed25519::pkcs8::Result<Self> {
        Ok(Self::new(SigningKey::from_pkcs8_der(bytes)?))
    }
}

impl EncodePrivateKey for EdDidKey {
    fn to_pkcs8_der(&self) -> ed25519::pkcs8::Result<ed25519::pkcs8::SecretDocument> {
        self.signing_key.to_pkcs8_der()
    }
}

impl EncodePublicKey for EdDidKey {
    fn to_public_key_der(&self) -> ed25519::pkcs8::spki::Result<ed25519::pkcs8::Document> {
        self.signing_key.verifying_key().to_public_key_der()
    }
}

impl SignerDid<Signature> for EdDidKey {
    fn did(&self) -> Result<String, anyhow::Error> {
        Ok(self.did())
    }
}

fn did_key_str(key: &VerifyingKey) -> String {
    format!(
        "did:key:{}",
        Ed25519KeyPair::from_public_key(key.as_bytes()).fingerprint()
    )
}
