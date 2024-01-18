//! Helpers for running isolated webserver instances
use crate::{
    app_state::{AppState, AppStateBuilder},
    db::{self, Conn, MIGRATIONS},
    dns::server::DnsServer,
    router::setup_app_router,
    settings::Dns,
    setups::test::{TestIpfsDatabase, TestSetup, TestVerificationCodeSender},
};
use anyhow::{anyhow, Context, Result};
use axum::{extract::connect_info::MockConnectInfo, Router};
use axum_server::service::SendService;
use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use fission_core::{ed_did_key::EdDidKey, username::Handle};
use std::net::SocketAddr;
use uuid::Uuid;

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
        let db_name = format!("fission_server_test_{}", Uuid::new_v4().simple());
        let postgres_url = format!("{}/postgres", base_url);

        let mut conn = PgConnection::establish(&postgres_url)?;

        let query = diesel::sql_query(format!("CREATE DATABASE {}", db_name).as_str());

        query
            .execute(&mut conn)
            .map_err(|e| anyhow!(e))
            .context(format!("Could not create database {}", db_name))?;

        let mut conn = PgConnection::establish(&format!("{}/{}", base_url, db_name))
            .context("Cannot connect to postgres database.")?;

        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow!(e))
            .context("Could not run migrations")?;

        let db_pool = db::pool(format!("{}/{}", base_url, db_name).as_str(), 1).await?;

        let dns_settings = Dns {
            server_port: 1053,
            default_soa: "dns1.fission.systems hostmaster.fission.codes 0 10800 3600 604800 3600"
                .to_string(),
            default_ttl: 1800,
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

    #[allow(unused)]
    pub fn ipfs_db(&self) -> &TestIpfsDatabase {
        &self.app_state.ipfs_db
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
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let postgres_url = format!("{}/postgres", self.base_url);

        let mut conn =
            PgConnection::establish(&postgres_url).expect("Cannot connect to postgres database.");

        let disconnect_users = format!(
            "SELECT pg_terminate_backend(pid)
             FROM pg_stat_activity
             WHERE datname = '{}';",
            self.db_name
        );

        diesel::sql_query(disconnect_users.as_str())
            .execute(&mut conn)
            .unwrap();

        let query = diesel::sql_query(format!("DROP DATABASE {}", self.db_name).as_str());

        query
            .execute(&mut conn)
            .expect(&format!("Could not drop database {}", self.db_name));
    }
}
