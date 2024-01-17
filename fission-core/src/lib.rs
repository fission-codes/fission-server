#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unreachable_pub)]

//! fission-core

pub mod authority;
pub mod capabilities;
pub mod common;
pub mod dns;
pub mod ed_did_key;
pub mod revocation;
pub mod serde_value_source;
pub mod username;
