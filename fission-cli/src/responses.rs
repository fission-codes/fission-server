use fission_core::common::Account;
use rs_ucan::ucan::Ucan;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountAndAuth {
    pub account: Account,
    pub ucans: Vec<Ucan>,
}
