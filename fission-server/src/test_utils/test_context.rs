use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::{self, Pool, MIGRATIONS},
    test_utils::MockVerificationCodeSender,
};

pub(crate) struct TestContext {
    base_url: String,
    db_name: String,
}

impl TestContext {
    pub(crate) fn new() -> Self {
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

        Self {
            base_url: base_url.to_string(),
            db_name: db_name.to_string(),
        }
    }

    pub(crate) async fn app_state(&self) -> AppState {
        AppState {
            db_pool: self.pool().await,
            verification_code_sender: Box::new(MockVerificationCodeSender),
        }
    }

    pub(crate) async fn pool(&self) -> Pool {
        db::pool(format!("{}/{}", self.base_url, self.db_name).as_str(), 1)
            .await
            .unwrap()
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
