#![allow(missing_docs)]

//! Database

pub mod connection;
pub mod migrations;
pub mod schema;

pub use connection::{connect, pool, Conn, Pool};
