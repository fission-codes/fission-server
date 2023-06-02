//! Generic ping route.

use crate::{
    authority::Authority,
    db::{self, Pool},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
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
    path = "/api/auth/email/verify",
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
    State(pool): State<Pool>,
    authority: Authority,
    Json(payload): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<Response>)> {
    if payload.did != authority.ucan.issuer() {
        Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("did must match ucan".to_string()),
        ))?;
    }

    /*

    I'm not including this here, but presumably we want this check, or something like it?
    Alternatively, we can use an invocation?

    This can be done within the authority extractor, presumably?

    if Settings::load()?.server()?.did != authority.ucan.audience() {
        Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Authorization UCAN must delegate to server DID".to_string()),
        ))?;
    }
    */

    let mut request = payload.clone();
    if request.compute_code_hash().is_err() {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to send request token.".to_string()),
        ));
    }

    log::info!(
        "Successfully computed code hash {}",
        request.code_hash.clone().unwrap()
    );

    let conn = db::connect(&pool).await;

    let insert_result = EmailVerification::new(conn.unwrap(), request.clone()).await;
    if insert_result.is_err() {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to create request token.".to_string()),
        ));
    }

    log::info!("Insertion to the database seemed to have worked!");

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
