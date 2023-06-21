//! Generic ping route.

use crate::{
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
    router::AppState,
    settings::Settings,
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
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<Response>)> {
    if payload.did != authority.ucan.issuer() {
        Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("`did` parameter must match the issuer of the UCAN presented in the Authorization header.".to_string()),
        ))?;
    }

    /*

    The age-old question, should this be an invocation, or is the REST endpoint enough here?

    For now, we're using regular UCANs. This check can be done within the authority extractor,
    but we're going to repeat ourselves for now until we're sure that we don't need different
    audiences for different methods.

    */

    let settings = Settings::load();
    if let Err(error) = settings {
        log::error!("Failed to load settings: {}", error);
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Internal Server Error."),
        ));
    }

    let server_did = settings.unwrap().server().did.clone();
    let ucan_aud = authority.ucan.audience();
    if ucan_aud != server_did {
        log::debug!(
            "Incorrect UCAN `aud` used. Expected {}, got {}.",
            server_did,
            ucan_aud
        );
        let error_msg = format!(
            "Authorization UCAN must delegate to this server's DID (expected {}, got {})",
            server_did, ucan_aud
        );
        return Err(AppError::new(StatusCode::BAD_REQUEST, Some(error_msg)));
    }

    let mut request = payload.clone();
    request.compute_code_hash()?;

    log::debug!(
        "Successfully computed code hash {}",
        request.code_hash.clone().unwrap()
    );

    let mut conn = db::connect(&state.db_pool).await?;

    EmailVerification::new(&mut conn, request.clone()).await?;

    request.send_code().await?;
    Ok((
        StatusCode::OK,
        Json(Response::new("Successfully sent request token".to_string())),
    ))
}
