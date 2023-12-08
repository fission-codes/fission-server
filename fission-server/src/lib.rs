#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unreachable_pub)]

//! fission-server

#[macro_use]
extern crate diesel_migrations;

pub mod app_state;
pub mod authority;
pub mod db;
pub mod dns;
pub mod docs;
pub mod error;
pub mod extract;
pub mod headers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod router;
pub mod routes;
pub mod settings;
pub mod setups;
pub mod tracer;
pub mod tracing_layers;

#[cfg(test)]
mod test_utils;
