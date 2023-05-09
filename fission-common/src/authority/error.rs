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
    InsufficientCapabilityScope,
    InvalidUcan { reason: String },
    MissingCredentials,
    MissingProofs { proofs_needed: Vec<String> },
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let note;

        let (status, json_value) = match self {
            Error::InsufficientCapabilityScope => (
                StatusCode::FORBIDDEN,
                json!({ "error": "Insufficient capability scope" }),
            ),

            Error::InvalidUcan { reason } => {
                note = format!("Invalid UCAN: {}", reason);
                (StatusCode::UNAUTHORIZED, json!({ "error": note.as_str() }))
            }
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
