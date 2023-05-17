#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unreachable_pub, private_in_public)]

//! fission-server

pub mod authority;
pub mod db;
pub mod docs;
pub mod error;
pub mod extract;
pub mod headers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod router;
pub mod routes;
pub mod schema;
pub mod settings;
pub mod tracer;
pub mod tracing_layers;
