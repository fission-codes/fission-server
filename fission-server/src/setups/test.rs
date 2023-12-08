//! Test server setup code

use crate::setups::IpfsDatabase;
use crate::setups::ServerSetup;
use crate::setups::VerificationCodeSender;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::{multihash::MultihashGeneric as Multihash, Cid};
use dashmap::{DashMap, DashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};

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
