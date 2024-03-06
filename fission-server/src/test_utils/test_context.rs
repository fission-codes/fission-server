//! Helpers for running isolated webserver instances
use super::{
    ephermeral_db::{create_ephermeral_db, destroy_ephermeral_db},
    route_builder::RouteBuilder,
};
use crate::{
    app_state::{AppState, AppStateBuilder},
    db::{self, Conn},
    dns::server::DnsServer,
    router::setup_app_router,
    settings::Dns,
    setups::test::{TestIpfsDatabase, TestSetup, TestVerificationCodeSender},
};
use anyhow::{Context, Result};
use axum::{extract::connect_info::MockConnectInfo, Router};
use axum_server::service::SendService;
use fission_core::{ed_did_key::EdDidKey, username::Handle};
use http::{Method, Uri};
use std::net::SocketAddr;

/// A reference to a running fission server in an isolated test environment
#[derive(Debug)]
pub struct TestContext {
    app: Router,
    app_state: AppState<TestSetup>,
    base_url: String,
    db_name: String,
}

impl TestContext {
    /// Create a new test context
    pub async fn new() -> Result<Self> {
        Self::new_with_state(|builder| builder).await
    }

    pub async fn new_with_state<F>(f: F) -> Result<Self>
    where
        F: FnOnce(AppStateBuilder<TestSetup>) -> AppStateBuilder<TestSetup>,
    {
        let base_url = "postgres://postgres:postgres@localhost:5432";
        let db_name = create_ephermeral_db(base_url, "fission_server_test")?;

        let db_pool = db::pool(&format!("{}/{}", base_url, db_name), 1).await?;

        let dns_settings = Dns {
            server_port: 1053,
            default_soa: "dns1.fission.systems hostmaster.fission.codes 0 10800 3600 604800 3600"
                .to_string(),
            default_ttl: 1800,
            dnslink_ttl: 10,
            origin: "localhost".to_string(),
            users_origin: "localhost".to_string(),
        };

        let keypair = EdDidKey::generate();

        let dns_server = DnsServer::new(&dns_settings, db_pool.clone(), keypair.did())
            .context("Could not initialize DNS server")?;

        let builder = AppStateBuilder::default()
            .with_dns_settings(dns_settings)
            .with_db_pool(db_pool)
            .with_ipfs_db(TestIpfsDatabase::default())
            .with_verification_code_sender(TestVerificationCodeSender::default())
            .with_server_keypair(keypair)
            .with_dns_server(dns_server);

        let app_state = f(builder).finalize().unwrap();

        let app = setup_app_router(app_state.clone())
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))))
            .into_service();

        Ok(Self {
            app,
            app_state,
            base_url: base_url.to_string(),
            db_name: db_name.to_string(),
        })
    }

    pub fn app(&self) -> Router {
        self.app.clone()
    }

    pub async fn get_db_conn(&self) -> Result<Conn<'_>> {
        Ok(self.app_state.db_pool.get().await?)
    }

    pub fn ipfs_db(&self) -> &TestIpfsDatabase {
        &self.app_state.blocks.ipfs_db()
    }

    pub fn verification_code_sender(&self) -> &TestVerificationCodeSender {
        &self.app_state.verification_code_sender
    }

    pub fn server_did(&self) -> &EdDidKey {
        &self.app_state.server_keypair
    }

    pub fn app_state(&self) -> &AppState<TestSetup> {
        &self.app_state
    }

    pub fn user_handle(&self, username: &str) -> Result<Handle> {
        Handle::new(username, &self.app_state.dns_settings.users_origin)
    }

    pub fn request<U>(&self, method: Method, path: U) -> RouteBuilder
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<http::Error>,
    {
        RouteBuilder::new(self.app(), method, path)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        destroy_ephermeral_db(&self.base_url, &self.db_name).unwrap();
    }
}
