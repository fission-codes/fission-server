use crate::traits::IpfsDatabase;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::{multihash::MultihashGeneric as Multihash, Cid};
use dashmap::{DashMap, DashSet};
use std::{io::Read, sync::Arc};

#[derive(Debug, Default, Clone)]
pub(crate) struct TestIpfsDatabase {
    inner: Arc<State>,
}

#[derive(Debug, Default)]
struct State {
    pinned_cids: DashSet<Cid>,
    #[allow(unused)]
    blocks: DashMap<Cid, Bytes>,
}

impl TestIpfsDatabase {
    #[allow(unused)]
    pub(crate) fn add(&self, mut data: impl Read) -> Result<Cid> {
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes)?;

        let hash = blake3::hash(&bytes);
        let cid = Cid::new_v1(0x55, Multihash::wrap(0x1e, hash.as_bytes())?);

        let bytes = Bytes::from(bytes);

        self.inner.blocks.insert(cid, bytes);
        Ok(cid)
    }
}

#[async_trait]
impl IpfsDatabase for TestIpfsDatabase {
    async fn pin_add(&self, cid: &str, _recursive: bool) -> Result<()> {
        let cid: Cid = cid.try_into()?;
        self.inner.pinned_cids.insert(cid);
        Ok(())
    }
}
