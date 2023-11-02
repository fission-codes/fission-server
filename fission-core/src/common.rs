//! Request and response data types that are common and useful between clients of and the fission server

use rs_ucan::ucan::Ucan;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Email verification request struct
#[derive(Deserialize, Serialize, Validate, Clone, Debug, ToSchema)]
pub struct EmailVerifyRequest {
    /// The email address of the user signing up
    #[validate(email)]
    pub email: String,
}

/// Account Request Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema, Validate)]
pub struct AccountCreationRequest {
    /// Username associated with the account
    pub username: String,
    /// Email address associated with the account
    #[validate(email)]
    pub email: String,
    /// Email verification code
    pub code: String,
}

/// Information about an account
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct AccountResponse {
    /// username, if associated
    pub username: Option<String>,
    /// email, if associated
    pub email: Option<String>,
}

/// Information about the DID of an account
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct DidResponse {
    /// The DID of this account
    pub did: String,
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
    /// A list of UCANs returned from the request
    pub ucans: Vec<Ucan>,
}
