//! Migration code

use anyhow::Result;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async_migrations::{embed_migrations, EmbeddedMigrations};

/// Embed migrations into binary
pub static MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Run migrations
pub async fn run(db_pool: &crate::db::Pool) -> Result<()> {
    let mut conn = crate::db::connect(db_pool).await?;

    conn.build_transaction()
        .deferrable()
        .read_write()
        .serializable()
        .run(|c| async move { MIGRATIONS.run_pending_migrations(c).await }.scope_boxed())
        .await?;

    Ok(())
}
