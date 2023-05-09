use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde_json::json;

///////////
// TYPES //
///////////

// Implements https://github.com/ucan-wg/ucan-as-bearer-token#33-errors
#[derive(Debug)]
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

        let (status, error_message) = match self {
            Error::InsufficientCapabilityScope => {
                (StatusCode::FORBIDDEN, "Insufficient capability scope")
            }
            Error::InvalidUcan { reason } => {
                note = format!("Invalid UCAN: {}", reason);
                (StatusCode::UNAUTHORIZED, note.as_str())
            }
            Error::MissingCredentials => (StatusCode::UNAUTHORIZED, "Missing credentials"),
            Error::MissingProofs { proofs_needed } => (StatusCode::NOT_EXTENDED, ""),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
