//! This abstracts fission server side-effects into "setups".
//!
//! This module defines the trait, submodules define test & production
//! collections of implementations.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::{multihash::Code, Cid};
use futures_util::Future;
use wnfs::common::{utils::CondSend, BlockStore, BlockStoreError};

pub mod local;
pub mod prod;
#[cfg(any(feature = "test_utils", test))]
pub mod test;

/// This trait groups type parameters to the server's `AppState` struct.
///
/// It captures the setup of the server, distinguishing between e.g.
/// unit testing & production setups.
pub trait ServerSetup: Clone + Send + Sync + 'static {
    /// Which implementation for an IPFS database to choose
    type IpfsDatabase: IpfsDatabase;
    /// Which implementation to use to send verification codes
    type VerificationCodeSender: VerificationCodeSender;
}

/// Provides functionality for storing IPFS data.
/// Abstracted away, so you can plug in a real kubo node
/// or an in-memory test database.
pub trait IpfsDatabase: Clone + Send + Sync {
    /// Pin a DAG by CID.
    fn pin_add(&self, cid: &str, recursive: bool) -> impl Future<Output = Result<()>> + Send;

    /// Update a recursive pin by CIDs
    /// <https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-pin-update>
    fn pin_update(
        &self,
        cid_before: &str,
        cid_after: &str,
        unpin: bool,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Add a block to the database
    /// <https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-block-put>
    fn block_put(
        &self,
        cid_codec: u64,
        mhtype: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Cid>> + Send;

    /// Get a block from the database
    /// <https://docs.ipfs.tech/reference/kubo/rpc/#api-v0-block-get>
    fn block_get(&self, cid: &str) -> impl Future<Output = Result<Option<Bytes>>> + Send;
}

/// The service that sends account verification codes
#[async_trait]
pub trait VerificationCodeSender: Clone + Send + Sync {
    /// Send the code associated with the email
    async fn send_code(&self, email: &str, code: &str) -> Result<()>;
}

impl<T: IpfsDatabase> IpfsDatabase for &T {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()> {
        (**self).pin_add(cid, recursive).await
    }

    async fn pin_update(&self, cid_before: &str, cid_after: &str, unpin: bool) -> Result<()> {
        (**self).pin_update(cid_before, cid_after, unpin).await
    }

    async fn block_put(&self, cid_codec: u64, mhtype: u64, data: Vec<u8>) -> Result<Cid> {
        (**self).block_put(cid_codec, mhtype, data).await
    }

    async fn block_get(&self, cid: &str) -> Result<Option<Bytes>> {
        (**self).block_get(cid).await
    }
}

/// A newtype wrapper for turning an `IpfsDatabase` into something that implements `BlockStore`
#[derive(Debug, Clone)]
pub struct DbBlockStore<T> {
    /// The underlying IpfsDatabase
    pub inner: T,
}

impl<T> From<T> for DbBlockStore<T> {
    fn from(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: IpfsDatabase> BlockStore for DbBlockStore<T> {
    async fn get_block(&self, cid: &Cid) -> Result<Bytes, BlockStoreError> {
        let Some(block) = self.inner.block_get(&cid.to_string()).await? else {
            return Err(BlockStoreError::CIDNotFound(*cid));
        };
        Ok(block)
    }

    async fn put_block(
        &self,
        bytes: impl Into<Bytes> + CondSend,
        codec: u64,
    ) -> Result<Cid, BlockStoreError> {
        let cid = self
            .inner
            .block_put(codec, Code::Blake3_256.into(), bytes.into().to_vec())
            .await?;
        Ok(cid)
    }

    async fn put_block_keyed(
        &self,
        cid: Cid,
        bytes: impl Into<Bytes> + CondSend,
    ) -> Result<(), BlockStoreError> {
        let actual_cid = self
            .inner
            .block_put(cid.codec(), cid.hash().code(), bytes.into().to_vec())
            .await?;
        if cid != actual_cid {
            return Err(BlockStoreError::Custom(anyhow!(
                "CID mismatch: Expected {cid}, but the block hashed to {actual_cid}"
            )));
        }
        Ok(())
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool, BlockStoreError> {
        Ok(self.inner.block_get(&cid.to_string()).await?.is_some())
    }
}
