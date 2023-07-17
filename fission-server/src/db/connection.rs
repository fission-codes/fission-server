//! Database configuration & connections

use std::time::Duration;

use anyhow::Result;
use bb8::PooledConnection;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{
    pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection, RunQueryDsl,
};
use tracing::log;

// 🧬

use crate::settings::Settings;

use super::__diesel_schema_migrations;

/// Type alias for the connection pool
pub type Pool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Type alias for the connection
pub type Conn<'a> = PooledConnection<'a, AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Build the database pool
pub async fn pool() -> Result<Pool> {
    let global_settings = Settings::load()?;
    let db_settings = global_settings.database();

    log::info!(
        "Connecting to database: {}, connect_timeout={}",
        db_settings.url,
        db_settings.connect_timeout
    );

    let config =
        AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(&db_settings.url);

    let pool = bb8::Pool::builder()
        .connection_timeout(Duration::from_secs(db_settings.connect_timeout))
        .build(config)
        .await
        .unwrap();

    Ok(pool)
}

/// Establish a connection
pub async fn connect(pool: &Pool) -> Result<Conn<'_>> {
    log::error!("trying to connect");
    let conn = pool.get().await?;
    Ok(conn)
}

/// Get the current schema version
pub async fn schema_version(conn: &mut Conn<'_>) -> Result<String> {
    __diesel_schema_migrations::table
        .select(__diesel_schema_migrations::version)
        .order(__diesel_schema_migrations::version.desc())
        .first(conn)
        .await
        .map_err(Into::into)
}
