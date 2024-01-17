//! Request and response data types that are common and useful between clients of and the fission server

use crate::username::{Handle, Username};
use rs_ucan::ucan::Ucan;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use utoipa::ToSchema;
use validator::Validate;

/// Email verification request struct
#[derive(Deserialize, Serialize, Validate, Clone, Debug, ToSchema)]
pub struct EmailVerifyRequest {
    /// The email address of the user signing up
    #[validate(email)]
    #[schema(example = "max.mustermann@example.com")]
    pub email: String,
}

/// Account Request Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema, Validate)]
pub struct AccountCreationRequest {
    /// Username associated with the account
    #[schema(example = "my_username")]
    pub username: Username,
    /// Email address associated with the account
    #[validate(email)]
    #[schema(example = "max.mustermann@example.com")]
    pub email: String,
    /// Email verification code
    #[schema(example = "123456")]
    pub code: String,
}

/// Request data for the account link route
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct AccountLinkRequest {
    /// Email verification code
    #[schema(example = "123456")]
    pub code: String,
}

/// Response type indiciating success
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SuccessResponse {
    /// Whether the response was successful
    pub success: bool,
}

/// Response type containing UCANs
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct UcansResponse {
    /// Ucans indexed by their canonical CID (base32, sha-256 and raw codec)
    #[schema(value_type = HashMap<String, String>)]
    pub ucans: BTreeMap<String, Ucan>,
    /// The subset of canonical CIDs of UCANs that are revoked
    #[schema(value_type = Vec<String>)]
    pub revoked: BTreeSet<String>,
}

impl UcansResponse {
    /// List unrevoked ucans
    pub fn into_unrevoked(self) -> impl Iterator<Item = Ucan> {
        let Self { ucans, revoked } = self;
        ucans.into_iter().filter_map(move |(canonical_cid, ucan)| {
            if revoked.contains(&canonical_cid) {
                None
            } else {
                Some(ucan)
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
/// Information about an account
pub struct Account {
    /// Account DID
    #[schema(example = "did:key:z6MkemkqoaUBYisJbrE9onCPgJoZve1yji2azp3oJo9W6u2A")]
    pub did: String,

    /// Username associated with the account
    #[schema(value_type = Option<String>, example = "boris.e9c7.name")]
    pub username: Option<Handle>,

    /// Email address associated with the account
    #[schema(example = "max.mustermann@example.com")]
    pub email: Option<String>,
}
