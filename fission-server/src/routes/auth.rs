//! Generic ping route.

use crate::{error::AppResult, router::AppState};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

use rand::Rng;

/// Email Parameter
#[derive(Deserialize, Clone, Debug, ToSchema)]
pub struct Email {
    email: String,
}

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
    path = "/api/auth/requestToken",
    request_body = Email,
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
    Json(payload): Json<Email>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let email = payload.email;

    let mut request_tokens = state.request_tokens.write().unwrap();

    // obviously this isn't the correct behaviour, just filling in the basics.
    request_tokens.remove(&email);
    let mut rng = rand::thread_rng();
    // This is maybe way too little entropy. That said, my bank sends me 5 digit codes. 🤷‍♂️
    let random_integer: u32 = rng.gen_range(10000..=99999);
    request_tokens.insert(email, random_integer);
    Ok((
        StatusCode::OK,
        Response::new("Successfully sent request token".to_string()).into(),
    ))
}
