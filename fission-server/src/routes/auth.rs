//! Generic ping route.

use crate::router::AppState;
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use rand::{distributions::Alphanumeric, Rng};

fn generate_random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect()
}

/// POST handler for requesting a new token by email
// #[utoipa::path(
//     post,
//     path = "/auth/requestToken",
//     request_body = CreateEmail,
//     responses(
//         (status = 200, description = "Successfully sent request token"),
//         (status = 400, description = "Invalid request"),
//         (status = 429, description = "Too many requests"),
//         (status = 500, description = "Internal Server Error", body=AppError)
//     )
// )]

/// Email Parameter
#[derive(Deserialize, Clone, Debug)]
pub struct CreateEmail {
    email: String,
}

/// POST handler for requesting a new token by email
pub async fn request_token(
    State(state): State<AppState>,
    Json(payload): Json<CreateEmail>,
) -> impl IntoResponse {
    let email = payload.email;

    let mut request_tokens = state.request_tokens.lock().expect("lock state");
    let request_token = request_tokens.get(&email);

    match request_token {
        Some(token) => (StatusCode::OK, format!("Some?! {}", token.to_string())),
        None => {
            let random_string = generate_random_string(10); // Length of the random string
            request_tokens.insert(email, random_string);
            (StatusCode::OK, "yeah".to_string())
        }
    };
}
