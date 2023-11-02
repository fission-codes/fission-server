use crate::traits::IpfsDatabase;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::{multihash::MultihashGeneric as Multihash, Cid};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io::Read,
    sync::{Arc, Mutex},
};

#[derive(Debug, Default, Clone)]
pub(crate) struct TestIpfsDatabase {
    inner: Arc<Mutex<RefCell<State>>>,
}

#[derive(Debug, Default)]
struct State {
    pinned_cids: HashSet<Cid>,
    #[allow(unused)]
    blocks: HashMap<Cid, Bytes>,
}

impl TestIpfsDatabase {
    #[allow(unused)]
    pub(crate) fn add(&self, mut data: impl Read) -> Result<Cid> {
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes)?;

        let hash = blake3::hash(&bytes);
        let cid = Cid::new_v1(0x55, Multihash::wrap(0x1e, hash.as_bytes())?);

        let bytes = Bytes::from(bytes);

        self.inner
            .lock()
            .unwrap()
            .borrow_mut()
            .blocks
            .insert(cid, bytes);
        Ok(cid)
    }
}

#[async_trait]
impl IpfsDatabase for TestIpfsDatabase {
    async fn pin_add(&self, cid: &str, _recursive: bool) -> Result<()> {
        let cid: Cid = cid.try_into()?;
        self.inner
            .lock()
            .unwrap()
            .borrow_mut()
            .pinned_cids
            .insert(cid);
        Ok(())
    }
}
