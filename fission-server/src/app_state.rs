//! The Axum Application State

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::extract::ws;
use dashmap::DashMap;
use dyn_clone::DynClone;
use futures::channel::mpsc::Sender;
use std::{net::SocketAddr, sync::Arc};

use crate::{db::Pool, traits::IpfsDatabase};

/// A channel for transmitting messages to a websocket peer
pub type WsPeer = Sender<ws::Message>;

/// A map of all websocket peers connected to each DID-specific channel
pub type WsPeerMap = Arc<DashMap<String, DashMap<SocketAddr, WsPeer>>>;

#[derive(Clone)]
/// Global application route state.
pub struct AppState<D: IpfsDatabase> {
    /// The database pool
    pub db_pool: Pool,
    /// The ipfs peers to be rendered in the ipfs/peers endpoint
    pub ipfs_peers: Vec<String>,
    /// Connection to what stores the IPFS blocks
    pub ipfs_db: D,
    /// The service that sends account verification codes
    pub verification_code_sender: Box<dyn VerificationCodeSender>,
    /// The currently connected websocket peers
    pub ws_peer_map: WsPeerMap,
}

#[derive(Default)]
/// Builder for [`AppState`]
pub struct AppStateBuilder<D: IpfsDatabase> {
    db_pool: Option<Pool>,
    ipfs_peers: Vec<String>,
    ipfs_db: Option<D>,
    verification_code_sender: Option<Box<dyn VerificationCodeSender>>,
}

impl<D: IpfsDatabase> AppStateBuilder<D> {
    /// Finalize the builder and return the [`AppState`]
    pub fn finalize(self) -> Result<AppState<D>> {
        let db_pool = self.db_pool.ok_or_else(|| anyhow!("db_pool is required"))?;

        let ipfs_peers = self.ipfs_peers;

        let ipfs_db = self.ipfs_db.ok_or_else(|| anyhow!("ipfs_db is required"))?;

        let verification_code_sender = self
            .verification_code_sender
            .ok_or_else(|| anyhow!("verification_code_sender is required"))?;

        Ok(AppState {
            db_pool,
            ipfs_peers,
            ipfs_db,
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
        self.ipfs_peers.extend(ipfs_peers);
        self
    }

    /// Set the ipfs database
    pub fn with_ipfs_db(mut self, ipfs_db: D) -> Self {
        self.ipfs_db = Some(ipfs_db);
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

impl<D: IpfsDatabase + std::fmt::Debug> std::fmt::Debug for AppState<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db_pool", &self.db_pool)
            .field("ipfs_peers", &self.ipfs_peers)
            .field("ipfs_db", &self.ipfs_db)
            .field("ws_peer_map", &self.ws_peer_map)
            .finish()
    }
}

impl<D: IpfsDatabase + std::fmt::Debug> std::fmt::Debug for AppStateBuilder<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateBuilder")
            .field("db_pool", &self.db_pool)
            .field("ipfs_peers", &self.ipfs_peers)
            .field("ipfs_db", &self.ipfs_db)
            .finish()
    }
}
