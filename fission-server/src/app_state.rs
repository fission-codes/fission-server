//! The Axum Application State

use anyhow::Result;
use async_trait::async_trait;
use dyn_clone::DynClone;
use std::fmt;

use crate::db::Pool;

#[derive(Clone)]
/// Global application route state.
pub struct AppState {
    /// The database pool
    pub db_pool: Pool,
    /// The service that sends account verification codes
    pub verification_code_sender: Box<dyn VerificationCodeSender>,
}

/// The service that sends account verification codes
#[async_trait]
pub trait VerificationCodeSender: DynClone + Send + Sync {
    /// Send the code associated with the email
    async fn send_code(&self, email: &str, code: &str) -> Result<()>;
}

dyn_clone::clone_trait_object!(VerificationCodeSender);

#[async_trait]
impl VerificationCodeSender for Box<dyn VerificationCodeSender> {
    async fn send_code(&self, email: &str, code: &str) -> Result<()> {
        self.as_ref().send_code(email, code).await
    }
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("db_pool", &self.db_pool)
            .finish()
    }
}
