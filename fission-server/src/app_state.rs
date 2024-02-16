//! The Axum Application State

use crate::{
    db::Pool,
    dns::server::DnsServer,
    routes::ws::WsPeerMap,
    settings::{self},
    setups::{DbBlockStore, IpfsDatabase, ServerSetup},
};
use anyhow::{anyhow, Result};
use car_mirror::cache::{CacheMissing, InMemoryCache};
use fission_core::ed_did_key::EdDidKey;
use std::sync::Arc;

#[derive(Clone)]
/// Global application route state.
pub struct AppState<S: ServerSetup> {
    /// Settings loaded from env variables & the settings.toml file
    pub dns_settings: Arc<settings::Dns>,
    /// The database pool
    pub db_pool: Pool,
    /// The ipfs peers to be rendered in the ipfs/peers endpoint
    pub ipfs_peers: Vec<String>,
    /// Anything related to storing, retrieving and caching information about blocks
    pub blocks: Blocks<S::IpfsDatabase>,
    /// The service that sends account verification codes
    pub verification_code_sender: S::VerificationCodeSender,
    /// The currently connected websocket peers
    pub ws_peer_map: Arc<WsPeerMap>,
    /// The server's decentralized identity (signing/private key)
    pub server_keypair: Arc<EdDidKey>,
    /// The DNS server state. Used for answering DoH queries
    pub dns_server: DnsServer,
}

/// Anything related to block storage (connection to kubo/something mocking kubo, caches, metadata)
#[derive(Clone, Debug)] // Clone is cheap, it's mostly structs-of-Arcs
pub struct Blocks<D: IpfsDatabase> {
    /// The blockstore stack based on the ipfs database
    pub store: CacheMissing<DbBlockStore<D>>,
    /// Cache for information about blocks for car mirror
    pub cache: InMemoryCache,
}

/// Cache capacity settings
#[derive(Debug)]
pub struct CacheCapacities {
    /// Of how many CIDs we remember whether we have them or not
    pub missing_block_cids: usize,
    /// How many CIDs to remember the links between
    pub reference_cids: usize,
}

impl<D: IpfsDatabase> Blocks<D> {
    /// Return the underlying IpfsDatabase
    pub fn ipfs_db(&self) -> &D {
        &self.store.inner.inner
    }
}

impl<D: IpfsDatabase> Blocks<D> {
    /// Initialize the blocks subsystem
    pub fn new(ipfs_db: D, approx_capacities: CacheCapacities) -> Self {
        Self {
            store: CacheMissing::new(
                approx_capacities.missing_block_cids,
                DbBlockStore::from(ipfs_db),
            ),
            cache: InMemoryCache::new(approx_capacities.reference_cids),
        }
    }
}

/// Builder for [`AppState`]
#[derive(Debug)]
pub struct AppStateBuilder<S: ServerSetup> {
    dns_settings: Option<settings::Dns>,
    db_pool: Option<Pool>,
    ipfs_peers: Vec<String>,
    ipfs_db: Option<S::IpfsDatabase>,
    verification_code_sender: Option<S::VerificationCodeSender>,
    server_keypair: Option<EdDidKey>,
    dns_server: Option<DnsServer>,
    ws_peer_map: Arc<WsPeerMap>,
}

impl<S: ServerSetup> Default for AppStateBuilder<S> {
    fn default() -> Self {
        Self {
            dns_settings: None,
            db_pool: None,
            ipfs_peers: Default::default(),
            ipfs_db: None,
            verification_code_sender: None,
            server_keypair: None,
            dns_server: None,
            ws_peer_map: Default::default(),
        }
    }
}

impl<S: ServerSetup> AppStateBuilder<S> {
    /// Finalize the builder and return the [`AppState`]
    pub fn finalize(self) -> Result<AppState<S>> {
        let dns_settings = Arc::new(
            self.dns_settings
                .ok_or_else(|| anyhow!("dns settings are required"))?,
        );

        let db_pool = self.db_pool.ok_or_else(|| anyhow!("db_pool is required"))?;

        let ipfs_peers = self.ipfs_peers;

        let ipfs_db = self.ipfs_db.ok_or_else(|| anyhow!("ipfs_db is required"))?;

        let verification_code_sender = self
            .verification_code_sender
            .ok_or_else(|| anyhow!("verification_code_sender is required"))?;

        let did = self
            .server_keypair
            .ok_or_else(|| anyhow!("did is required"))?;

        let dns_server = self
            .dns_server
            .ok_or_else(|| anyhow!("dns_server is required"))?;

        let ws_peer_map = self.ws_peer_map;

        Ok(AppState {
            dns_settings,
            db_pool,
            ipfs_peers,
            verification_code_sender,
            ws_peer_map,
            server_keypair: Arc::new(did),
            dns_server,
            blocks: Blocks::new(
                ipfs_db,
                // TODO(matheus23): make these numbers configurable
                CacheCapacities {
                    reference_cids: 100_000,
                    missing_block_cids: 150_000,
                },
            ),
        })
    }

    /// Set settings
    pub fn with_dns_settings(mut self, dns_settings: settings::Dns) -> Self {
        self.dns_settings = Some(dns_settings);
        self
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

    /// Set the server's keypair
    pub fn with_server_keypair(mut self, server_keypair: EdDidKey) -> Self {
        self.server_keypair = Some(server_keypair);
        self
    }

    /// Set the DNS server
    pub fn with_dns_server(mut self, dns_server: DnsServer) -> Self {
        self.dns_server = Some(dns_server);
        self
    }

    /// Set the websocket peer map
    pub fn with_ws_peer_map(mut self, ws_peer_map: Arc<WsPeerMap>) -> Self {
        self.ws_peer_map = ws_peer_map;
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
            .field("blocks", &self.blocks)
            .field("ws_peer_map", &self.ws_peer_map)
            .field("verification_code_sender", &self.verification_code_sender)
            .finish()
    }
}
