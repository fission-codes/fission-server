use std::net::SocketAddr;

use axum::{extract::connect_info::MockConnectInfo, Router};
use axum_server::service::SendService;
use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use uuid::Uuid;

use crate::{
    app_state::{AppState, AppStateBuilder},
    db::{self, Conn, MIGRATIONS},
    router::setup_app_router,
    test_utils::MockVerificationCodeSender,
};

pub(crate) struct TestContext {
    app: Router,
    app_state: AppState,
    base_url: String,
    db_name: String,
}

impl TestContext {
    pub(crate) async fn new() -> Self {
        Self::new_with_state(|builder| builder).await
    }

    pub(crate) async fn new_with_state<F>(f: F) -> Self
    where
        F: FnOnce(AppStateBuilder) -> AppStateBuilder,
    {
        let base_url = "postgres://postgres:postgres@localhost:5432";
        let db_name = format!("fission_server_test_{}", Uuid::new_v4().simple());
        let postgres_url = format!("{}/postgres", base_url);

        let mut conn =
            PgConnection::establish(&postgres_url).expect("Cannot connect to postgres database.");

        let query = diesel::sql_query(format!("CREATE DATABASE {}", db_name).as_str());

        query
            .execute(&mut conn)
            .expect(format!("Could not create database {}", db_name).as_str());

        let mut conn = PgConnection::establish(&format!("{}/{}", base_url, db_name))
            .expect("Cannot connect to postgres database.");

        conn.run_pending_migrations(MIGRATIONS)
            .expect("Could not run migrations");

        let db_pool = db::pool(format!("{}/{}", base_url, db_name).as_str(), 1)
            .await
            .unwrap();

        let builder = AppStateBuilder::default()
            .with_db_pool(db_pool)
            .with_verification_code_sender(MockVerificationCodeSender);

        let app_state = f(builder).finalize().unwrap();

        let app = setup_app_router(app_state.clone())
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))))
            .into_service();

        Self {
            app,
            app_state,
            base_url: base_url.to_string(),
            db_name: db_name.to_string(),
        }
    }

    pub(crate) fn app(&self) -> Router {
        self.app.clone()
    }

    pub(crate) async fn get_db_conn(&self) -> Conn<'_> {
        self.app_state.db_pool.get().await.unwrap()
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
