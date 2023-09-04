//! All custom traits defined in fission-server
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ipfs_api::IpfsApi;

/// This trait groups type parameters to the server's `AppState` struct.
///
/// It captures the setup of the server, distinguishing between e.g.
/// unit testing & production setups.
pub trait ServerSetup: Clone + Send + Sync {
    /// Which implementation for an IPFS database to choose
    type IpfsDatabase: IpfsDatabase;
}

/// Provides functionality for storing IPFS data.
/// Abstracted away, so you can plug in a real kubo node
/// or an in-memory test database.
#[async_trait]
pub trait IpfsDatabase: Clone + Send + Sync {
    /// Pin a DAG by CID.
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()>;
}

/// An implementation of `IpfsDatabase` which connects to a locally-running
/// IPFS kubo node.
#[derive(Clone, Default)]
pub struct IpfsHttpApiDatabase(ipfs_api::IpfsClient);

impl std::fmt::Debug for IpfsHttpApiDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IpfsHttpApiDatabase").finish()
    }
}

#[async_trait]
impl IpfsDatabase for IpfsHttpApiDatabase {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()> {
        self.0
            .pin_add(cid, recursive)
            .await
            .map_err(|e| anyhow!("Failed to pin CID: {e}"))?;
        Ok(())
    }
}
