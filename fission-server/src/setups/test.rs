//! Test server setup code

use crate::setups::{IpfsDatabase, ServerSetup, VerificationCodeSender};
use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::{
    multihash::{Code, MultihashDigest},
    Cid,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default)]
pub struct TestSetup;

impl ServerSetup for TestSetup {
    type IpfsDatabase = TestIpfsDatabase;
    type VerificationCodeSender = TestVerificationCodeSender;
}

#[derive(Debug, Default, Clone)]
pub struct TestIpfsDatabase {
    inner: Arc<State>,
}

#[derive(Debug, Default)]
struct State {
    pinned_cids: RwLock<BTreeSet<Cid>>,
    blocks: DashMap<Cid, Bytes>,
}

impl IpfsDatabase for TestIpfsDatabase {
    async fn pin_add(&self, cid: &str, _recursive: bool) -> Result<()> {
        let cid: Cid = cid.try_into()?;
        self.inner.pinned_cids.write().insert(cid);
        Ok(())
    }

    async fn pin_update(&self, cid_before: &str, cid_after: &str, unpin: bool) -> Result<()> {
        let cid_before: Cid = cid_before.try_into()?;
        let cid_after: Cid = cid_after.try_into()?;

        let mut pins = self.inner.pinned_cids.write();

        if !pins.contains(&cid_before) {
            bail!("Expected to update pin from {cid_before} to {cid_after}, but {cid_before} isn't pinned.");
        }

        if unpin {
            pins.remove(&cid_before);
        }

        pins.insert(cid_after);

        Ok(())
    }

    async fn block_put(&self, cid_codec: u64, mhtype: u64, data: Vec<u8>) -> Result<Cid> {
        let hash = Code::try_from(mhtype)
            .context("Unsupported multihash type")?
            .digest(&data);

        let cid = Cid::new_v1(cid_codec, hash);

        self.inner.blocks.insert(cid, Bytes::from(data));

        Ok(cid)
    }

    async fn block_get(&self, cid: &str) -> Result<Option<Bytes>> {
        let cid = Cid::try_from(cid).context("Parsing CID for block/get")?;
        Ok(self.inner.blocks.get(&cid).map(|rf| rf.clone())) // cheap clone
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestVerificationCodeSender {
    emails: Arc<Mutex<Vec<(String, String)>>>,
}

impl TestVerificationCodeSender {
    pub fn get_emails(&self) -> Vec<(String, String)> {
        self.emails.lock().unwrap().clone()
    }
}

#[async_trait]
impl VerificationCodeSender for TestVerificationCodeSender {
    async fn send_code(&self, email: &str, code: &str) -> Result<()> {
        self.emails
            .lock()
            .unwrap()
            .push((email.to_string(), code.to_string()));
        Ok(())
    }
}
