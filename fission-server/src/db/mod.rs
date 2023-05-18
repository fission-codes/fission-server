//! Database

pub mod connection;

#[allow(missing_docs, unused_imports)]
pub mod schema;

pub use connection::{connect, pool, Conn, Pool};
