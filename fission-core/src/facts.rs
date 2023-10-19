//! Fact data types used in UCANs by the fission server & its clients

use serde::{Deserialize, Serialize};

/// This stores the information a client has to provide when returning with an
/// email verification code.
///
/// Email verification needs two factors:
/// 1. Access to read emails
/// 2. Access to the keypair on the device that originally created the email verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationFacts {
    /// The verification code
    pub code: u64,
    /// The DID that was originally used to initiate the email verification
    pub did: String,
}
