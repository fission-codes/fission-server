//! Database configuration & connections

use std::time::Duration;

use anyhow::Result;
use bb8::PooledConnection;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{
    pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection, RunQueryDsl,
};
use tracing::log;

// 🧬

use super::__diesel_schema_migrations;

/// Type alias for the connection pool
pub type Pool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Type alias for the connection
pub type Conn<'a> = PooledConnection<'a, AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Build the database pool
pub async fn pool(url: &str, connect_timeout: u64) -> Result<Pool> {
    log::info!(
        "Connecting to database: {}, connect_timeout={}",
        &url,
        connect_timeout
    );

    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(url);

    let pool = bb8::Pool::builder()
        .connection_timeout(Duration::from_secs(connect_timeout))
        .build(config)
        .await
        .unwrap();

    Ok(pool)
}

/// Establish a connection
pub async fn connect(pool: &Pool) -> Result<Conn<'_>> {
    log::debug!("Connecting to the database");
    pool.get()
        .await
        .map_err(|_| anyhow::anyhow!("Failed to connect to database"))
}

/// Get the current schema version
pub async fn schema_version(conn: &mut Conn<'_>) -> Result<Option<String>> {
    __diesel_schema_migrations::table
        .select(__diesel_schema_migrations::version)
        .order(__diesel_schema_migrations::version.desc())
        .first(conn)
        .await
        .optional()
        .map_err(Into::into)
}
