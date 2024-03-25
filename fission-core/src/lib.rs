#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unreachable_pub)]

//! fission-core, shared code between the server & clients

pub mod authority;
pub mod capabilities;
pub mod caps;
pub mod common;
pub mod dns;
pub mod ed_did_key;
pub mod revocation;
pub mod serde_value_source;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
pub mod username;
