//! This abstracts fission server side-effects into "setups".
//!
//! This module defines the trait, submodules define test & production
//! collections of implementations.
use anyhow::Result;
use async_trait::async_trait;

pub mod local;
pub mod prod;
#[cfg(test)]
pub mod test;

/// This trait groups type parameters to the server's `AppState` struct.
///
/// It captures the setup of the server, distinguishing between e.g.
/// unit testing & production setups.
pub trait ServerSetup: Clone + Send + Sync {
    /// Which implementation for an IPFS database to choose
    type IpfsDatabase: IpfsDatabase;
    /// Which implementation to use to send verification codes
    type VerificationCodeSender: VerificationCodeSender;
}

/// Provides functionality for storing IPFS data.
/// Abstracted away, so you can plug in a real kubo node
/// or an in-memory test database.
#[async_trait]
pub trait IpfsDatabase: Clone + Send + Sync {
    /// Pin a DAG by CID.
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()>;
}

/// The service that sends account verification codes
#[async_trait]
pub trait VerificationCodeSender: Clone + Send + Sync {
    /// Send the code associated with the email
    async fn send_code(&self, email: &str, code: &str) -> Result<()>;
}
