//! Database

pub mod connection;

pub use connection::{connect, pool, Conn, Pool};
