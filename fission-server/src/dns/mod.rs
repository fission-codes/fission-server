//! DNS

use self::response_handler::Handle;
use crate::{
    db::Pool,
    dns::user_dids::{did_record_set, record_set, UserDidsAuthority},
    settings::Dns,
};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use hickory_server::{
    authority::{Authority, Catalog, ZoneType},
    proto::{
        rr::{rdata, RData, Record, RecordType, RrKey},
        serialize::txt::RDataParser,
    },
    resolver::{config::NameServerConfigGroup, Name},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::broadcast;

pub mod response;
pub mod response_handler;
pub mod user_dids;

/// State for serving DNS
#[derive(Clone)]
pub struct DnsServer {
    /// The authority that handles the server's main `_did` DNS TXT record lookups
    pub server_did_authority: Arc<InMemoryAuthority>,
    /// The authority that handles all user `_did` DNS TXT record lookups
    pub user_did_authority: Arc<UserDidsAuthority>,
    /// The catch-all authority that forwards requests to secondary nameservers
    pub forwarder: Arc<ForwardAuthority>,
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsState")
            .field("server_did_authority", &"InMemoryAuthority {{ .. }}")
            .field("user_did_authority", &self.user_did_authority)
            .field("forwarder", &"ForwardAuthority {{ .. }}")
            .finish()
    }
}

impl DnsServer {
    /// Create a DNS server given some settings, a connection to the DB for DID-by-username lookups
    /// and the server DID to serve under `_did.<origin>`.
    pub fn new(settings: &Dns, db_pool: Pool, server_did: String) -> Result<Self> {
        let default_soa = RData::parse(
            RecordType::SOA,
            settings.default_soa.split_ascii_whitespace(),
            None,
        )?
        .into_soa()
        .map_err(|_| anyhow!("Couldn't parse SOA: {}", settings.default_soa))?;

        Ok(Self {
            server_did_authority: Arc::new(Self::setup_server_did_authority(
                settings,
                server_did,
                default_soa.clone(),
            )?),
            user_did_authority: Arc::new(Self::setup_user_did_authority(
                settings,
                db_pool,
                default_soa,
            )?),
            forwarder: Arc::new(Self::setup_forwarder()?),
        })
    }

    /// Handle a DNS request
    pub async fn answer_request(&self, request: Request) -> Result<Bytes> {
        tracing::info!(?request, "Got DNS request");

        let (tx, mut rx) = broadcast::channel(1);
        let response_handle = Handle(tx);

        self.handle_request(&request, response_handle).await;

        tracing::debug!("Done handling request, trying to resolve response");
        Ok(rx.recv().await?)
    }

    fn setup_server_did_authority(
        settings: &Dns,
        server_did: String,
        default_soa: rdata::SOA,
    ) -> Result<InMemoryAuthority> {
        let server_origin = Name::parse(&settings.origin, Some(&Name::root()))?;
        let server_did_name = Name::parse("_did", Some(&server_origin))?;
        let serial = default_soa.serial();
        let did_rset = did_record_set(&server_did_name, server_did, settings.default_ttl, serial);
        let server_did_authority = InMemoryAuthority::new(
            server_did_name.clone(),
            BTreeMap::from([
                (
                    RrKey::new(server_did_name.clone().into(), RecordType::TXT),
                    did_rset,
                ),
                (
                    RrKey::new(server_did_name.clone().into(), RecordType::SOA),
                    record_set(
                        &server_did_name,
                        RecordType::SOA,
                        serial,
                        Record::from_rdata(
                            server_did_name.clone(),
                            1209600,
                            RData::SOA(default_soa),
                        ),
                    ),
                ),
            ]),
            ZoneType::Primary,
            false,
        )
        .map_err(|e| anyhow!(e))?;

        Ok(server_did_authority)
    }

    fn setup_user_did_authority(
        settings: &Dns,
        db_pool: Pool,
        default_soa: rdata::SOA,
    ) -> Result<UserDidsAuthority> {
        let origin_name = Name::parse(&settings.origin, Some(&Name::root()))?;
        Ok(UserDidsAuthority::new(
            db_pool,
            origin_name.into(),
            default_soa,
            settings.default_ttl,
        ))
    }

    fn setup_forwarder() -> Result<ForwardAuthority> {
        let config = ForwardConfig {
            name_servers: NameServerConfigGroup::cloudflare(),
            options: None,
        };

        let forwarder = ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &config)
            .map_err(|e| anyhow!(e))?;

        Ok(forwarder)
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        // A catalog is very light-weight. Just a hashmap.
        // Shouldn't be a big cost to initialize for requests.
        let mut catalog = Catalog::new();
        catalog.upsert(
            self.user_did_authority.origin().clone(),
            Box::new(Arc::clone(&self.user_did_authority)),
        );
        catalog.upsert(
            self.server_did_authority.origin().clone(),
            Box::new(Arc::clone(&self.server_did_authority)),
        );
        catalog.upsert(Name::root().into(), Box::new(Arc::clone(&self.forwarder)));

        catalog.handle_request(request, response_handle).await
    }
}
