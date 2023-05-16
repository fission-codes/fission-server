//! Authority error type and implementations

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde_json::json;

///////////
// TYPES //
///////////

#[derive(Debug)]
/// Implements https://github.com/ucan-wg/ucan-as-bearer-token#33-errors
pub enum Error {
    /// UCAN does not include sufficient authority to perform the requestor's action
    InsufficientCapabilityScope,

    /// UCAN is expired, revoked, malformed, or otherwise invalid
    InvalidUcan {
        /// Reason why the UCAN is invalid
        reason: String,
    },

    /// UCAN is missing
    MissingCredentials,

    /// Referenced proofs are missing from the cache
    MissingProofs {
        /// The CIDs of the proofs that are missing
        proofs_needed: Vec<String>,
    },
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, json_value) = match self {
            Error::InsufficientCapabilityScope => (
                StatusCode::FORBIDDEN,
                json!({ "error": "Insufficient capability scope" }),
            ),

            Error::InvalidUcan { reason } => (
                StatusCode::UNAUTHORIZED,
                json!({ "error": format!("Invalid UCAN: {}", reason) }),
            ),
            Error::MissingCredentials => (
                StatusCode::UNAUTHORIZED,
                json!({ "error": "Missing credentials" }),
            ),
            Error::MissingProofs { proofs_needed } => {
                (StatusCode::NOT_EXTENDED, json!({ "prf": proofs_needed }))
            }
        };

        let body = Json(json_value);
        (status, body).into_response()
    }
}
