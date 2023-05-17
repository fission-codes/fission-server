//! Database

pub mod connection;
pub mod migrations;

pub use connection::{connect, pool, Conn, Pool};
