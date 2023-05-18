//! Generic ping route.

use crate::{
    authority::Authority,
    error::{AppError, AppResult},
    models::email_verification,
    router::AppState,
};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use serde::Serialize;

use utoipa::ToSchema;

use tracing::log;

/// Response for Request Token
#[derive(Serialize, Debug, ToSchema)]
pub struct Response {
    msg: String,
}

impl Response {
    /// Create a new Response
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// POST handler for requesting a new token by email
#[utoipa::path(
    post,
    path = "/api/auth/emailVerification",
    request_body = email_verification::Request,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully sent request token", body=Response),
        (status = 400, description = "Invalid request"),
        (status = 429, description = "Too many requests"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// POST handler for requesting a new token by email
pub async fn request_token(
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let email = payload.email.clone();

    let mut request_tokens = state.request_tokens.write().await;

    if payload.did != authority.ucan.issuer() {
        Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("DID must match Audience".to_string()),
        ))?;
    }

    // obviously this isn't the correct behaviour, just filling in the basics.
    request_tokens.remove(&email);

    let mut request = payload.clone();
    if request.compute_code_hash().is_err() {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to send request token.".to_string()),
        ));
    } else {
        log::info!(
            "Successfully computed code hash {}",
            request.code_hash.clone().unwrap()
        );
        request_tokens.insert(email, request.clone());
    }

    let email_response = request.send_code().await;
    if email_response.is_ok() {
        Ok((
            StatusCode::OK,
            Json(Response::new("Successfully sent request token".to_string())),
        ))
    } else {
        Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to send request token".to_string()),
        ))
    }
}
