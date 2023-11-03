//! The Axum Application State

use anyhow::{anyhow, Result};
use axum::extract::ws;
use dashmap::DashMap;
use fission_core::ed_did_key::EdDidKey;
use futures::channel::mpsc::Sender;
use std::{net::SocketAddr, sync::Arc};

use crate::{db::Pool, traits::ServerSetup};

/// A channel for transmitting messages to a websocket peer
pub type WsPeer = Sender<ws::Message>;

/// A map of all websocket peers connected to each DID-specific channel
pub type WsPeerMap = Arc<DashMap<String, DashMap<SocketAddr, WsPeer>>>;

#[derive(Clone)]
/// Global application route state.
pub struct AppState<S: ServerSetup> {
    /// The database pool
    pub db_pool: Pool,
    /// The ipfs peers to be rendered in the ipfs/peers endpoint
    pub ipfs_peers: Vec<String>,
    /// Connection to what stores the IPFS blocks
    pub ipfs_db: S::IpfsDatabase,
    /// The service that sends account verification codes
    pub verification_code_sender: S::VerificationCodeSender,
    /// The currently connected websocket peers
    pub ws_peer_map: WsPeerMap,
    /// The server's decentralized identity (signing/private key)
    pub server_key: Arc<EdDidKey>,
}

/// Builder for [`AppState`]
pub struct AppStateBuilder<S: ServerSetup> {
    db_pool: Option<Pool>,
    ipfs_peers: Vec<String>,
    ipfs_db: Option<S::IpfsDatabase>,
    verification_code_sender: Option<S::VerificationCodeSender>,
    did: Option<EdDidKey>,
}

impl<S: ServerSetup> Default for AppStateBuilder<S> {
    fn default() -> Self {
        Self {
            db_pool: None,
            ipfs_peers: Default::default(),
            ipfs_db: None,
            verification_code_sender: None,
            did: None,
        }
    }
}

impl<S: ServerSetup> AppStateBuilder<S> {
    /// Finalize the builder and return the [`AppState`]
    pub fn finalize(self) -> Result<AppState<S>> {
        let db_pool = self.db_pool.ok_or_else(|| anyhow!("db_pool is required"))?;

        let ipfs_peers = self.ipfs_peers;

        let ipfs_db = self.ipfs_db.ok_or_else(|| anyhow!("ipfs_db is required"))?;

        let verification_code_sender = self
            .verification_code_sender
            .ok_or_else(|| anyhow!("verification_code_sender is required"))?;

        let did = self.did.ok_or_else(|| anyhow!("did is required"))?;

        Ok(AppState {
            db_pool,
            ipfs_peers,
            ipfs_db,
            verification_code_sender,
            ws_peer_map: Default::default(),
            server_key: Arc::new(did),
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
    pub fn with_ipfs_db(mut self, ipfs_db: S::IpfsDatabase) -> Self {
        self.ipfs_db = Some(ipfs_db);
        self
    }

    /// Set the service that sends account verification codes
    pub fn with_verification_code_sender(
        mut self,
        verification_code_sender: S::VerificationCodeSender,
    ) -> Self {
        self.verification_code_sender = Some(verification_code_sender);
        self
    }

    /// Set the server's DID
    pub fn with_did(mut self, did: EdDidKey) -> Self {
        self.did = Some(did);
        self
    }
}

impl<S> std::fmt::Debug for AppState<S>
where
    S: ServerSetup,
    S::IpfsDatabase: std::fmt::Debug,
    S::VerificationCodeSender: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db_pool", &self.db_pool)
            .field("ipfs_peers", &self.ipfs_peers)
            .field("ipfs_db", &self.ipfs_db)
            .field("ws_peer_map", &self.ws_peer_map)
            .field("verification_code_sender", &self.verification_code_sender)
            .finish()
    }
}

impl<S> std::fmt::Debug for AppStateBuilder<S>
where
    S: ServerSetup,
    S::IpfsDatabase: std::fmt::Debug,
    S::VerificationCodeSender: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateBuilder")
            .field("db_pool", &self.db_pool)
            .field("ipfs_peers", &self.ipfs_peers)
            .field("ipfs_db", &self.ipfs_db)
            .field("verification_code_sender", &self.verification_code_sender)
            .finish()
    }
}
