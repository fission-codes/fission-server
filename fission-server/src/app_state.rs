//! The Axum Application State

use anyhow::Result;
use async_trait::async_trait;
use axum::extract::ws;
use dashmap::DashMap;
use dyn_clone::DynClone;
use futures::channel::mpsc::Sender;
use std::{fmt, net::SocketAddr, sync::Arc};

use crate::db::Pool;

/// A channel for transmitting messages to a websocket peer
pub type WsPeer = Sender<ws::Message>;

/// A map of all websocket peers connected to each DID-specific channel
pub type WsPeerMap = Arc<DashMap<String, DashMap<SocketAddr, WsPeer>>>;

#[derive(Clone)]
/// Global application route state.
pub struct AppState {
    /// The database pool
    pub db_pool: Pool,
    /// The ipfs peers to be rendered in the ipfs/peers endpoint
    pub ipfs_peers: Vec<String>,
    /// The service that sends account verification codes
    pub verification_code_sender: Box<dyn VerificationCodeSender>,
    /// The currently connected websocket peers
    pub ws_peer_map: WsPeerMap,
}

#[derive(Default)]
/// Builder for [`AppState`]
pub struct AppStateBuilder {
    db_pool: Option<Pool>,
    ipfs_peers: Option<Vec<String>>,
    verification_code_sender: Option<Box<dyn VerificationCodeSender>>,
}

impl AppStateBuilder {
    /// Finalize the builder and return the [`AppState`]
    pub fn finalize(self) -> Result<AppState> {
        let db_pool = self
            .db_pool
            .ok_or_else(|| anyhow::anyhow!("db_pool is required"))?;

        let ipfs_peers = self
            .ipfs_peers
            .ok_or_else(|| anyhow::anyhow!("ipfs_peers is required"))?;

        let verification_code_sender = self
            .verification_code_sender
            .ok_or_else(|| anyhow::anyhow!("verification_code_sender is required"))?;

        Ok(AppState {
            db_pool,
            ipfs_peers,
            verification_code_sender,
            ws_peer_map: Default::default(),
        })
    }

    /// Set the database pool
    pub fn with_db_pool(mut self, db_pool: Pool) -> Self {
        self.db_pool = Some(db_pool);
        self
    }

    /// Set the ipfs peers
    pub fn with_ipfs_peers(mut self, ipfs_peers: Vec<String>) -> Self {
        self.ipfs_peers = Some(ipfs_peers);
        self
    }

    /// Set the service that sends account verification codes
    pub fn with_verification_code_sender<T>(mut self, verification_code_sender: T) -> Self
    where
        T: VerificationCodeSender + 'static,
    {
        self.verification_code_sender = Some(Box::new(verification_code_sender));
        self
    }
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

impl fmt::Debug for AppStateBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppStateBuilder")
            .field("db_pool", &self.db_pool)
            .finish()
    }
}
