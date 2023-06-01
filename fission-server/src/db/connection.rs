//! Database configuration & connections

use anyhow::Result;
use bb8::PooledConnection;
use diesel_async::{pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection};
use tracing::log;

// 🧬

use crate::settings::Settings;

/// Type alias for the connection pool
pub type Pool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Type alias for the connection
pub type Conn<'a> = PooledConnection<'a, AsyncDieselConnectionManager<AsyncPgConnection>>;

/// Build the database pool
pub async fn pool() -> Result<Pool> {
    let global_settings = Settings::load()?;
    let db_settings = global_settings.database();

    log::info!("Connecting to database: {}", db_settings.url);

    let config =
        AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(&db_settings.url);
    let pool = bb8::Pool::builder().build(config).await?;

    Ok(pool)
}

/// Establish a connection
pub async fn connect(pool: &Pool) -> Result<Conn<'_>> {
    log::error!("trying to connect");
    let conn = pool.get().await?;
    Ok(conn)
}
