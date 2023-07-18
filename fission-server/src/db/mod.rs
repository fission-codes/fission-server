//! Database

pub mod connection;

#[allow(missing_docs, unused_imports)]
pub mod schema;

pub use connection::{connect, pool, schema_version, Conn, Pool};

diesel::table! {
    /// Redefine the Diesel schema migrations table for use in healthchecks,
    /// to verify that all pending migrations have been applied.
    ///
    /// Copied from: diesel_migrations::migration_harness
    #[allow(missing_docs)]
    __diesel_schema_migrations (version) {
        version -> VarChar,
        run_on -> Timestamp,
    }
}
