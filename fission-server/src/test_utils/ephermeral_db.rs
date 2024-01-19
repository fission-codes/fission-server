//! Setup and destruction of an ephemeral DB for testing setups
use crate::db::MIGRATIONS;
use anyhow::{anyhow, Context as _, Result};
use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::MigrationHarness;
use uuid::Uuid;

/// Create a new ephemeral DB.
pub fn create_ephermeral_db(base_url: &str, prefix: &str) -> Result<String> {
    let db_name = format!("{prefix}_{}", Uuid::new_v4().simple());

    tracing::debug!(?db_name, "Using ephemeral DB");

    let postgres_url = format!("{}/postgres", base_url);

    let conn = &mut PgConnection::establish(&postgres_url)?;

    diesel::sql_query(format!("CREATE DATABASE {}", &db_name))
        .execute(conn)
        .map_err(|e| anyhow!(e))
        .context(format!("Could not create database {}", &db_name))?;

    let mut conn = PgConnection::establish(&format!("{}/{}", base_url, db_name))
        .context("Cannot connect to postgres database.")?;

    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow!(e))
        .context("Could not run migrations")?;

    Ok(db_name)
}

/// Destroy an ephemeral DB
pub fn destroy_ephermeral_db(base_url: &str, db_name: &str) -> Result<()> {
    tracing::debug!(?db_name, "Tearing down ephemeral DB");

    let postgres_url = format!("{}/postgres", base_url);

    let conn = &mut PgConnection::establish(&postgres_url)
        .context("Cannot connect to postgres database.")?;

    let disconnect_users = format!(
        "SELECT pg_terminate_backend(pid)
         FROM pg_stat_activity
         WHERE datname = '{}';",
        db_name
    );

    diesel::sql_query(disconnect_users).execute(conn)?;

    let query = diesel::sql_query(format!("DROP DATABASE {}", db_name));

    query
        .execute(conn)
        .context(format!("Could not drop database {}", db_name))?;

    Ok(())
}
