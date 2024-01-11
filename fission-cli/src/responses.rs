use rs_ucan::ucan::Ucan;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountCreationResponse {
    pub account: AccountInfo,
    pub ucans: Vec<Ucan>,
}

/// Information about an account
#[derive(Deserialize, Serialize, Debug)]
pub struct AccountInfo {
    /// username, if associated
    pub username: Option<String>,
    /// email, if associated
    pub email: Option<String>,
}
