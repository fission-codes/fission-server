//! Account routes

use crate::{error::AppResult, router::AppState};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

/// AccountResponse Enum
#[derive(Debug)]
pub enum AccountResponse {
    /// Account created
    Created(Json<Account>),
    /// Bad Request
    BadRequest(Json<Response>),
}

/// Account Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Account {
    name: String,
    email: String,
    did: String,
}

impl Account {
    /// Create a new instance of [Account]
    pub fn new(name: String, email: String, did: String) -> Self {
        Self { name, email, did }
    }
}

/// Response Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Response {
    msg: String,
}

impl Response {
    /// Create a new instance of [Response]
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// POST handler for requesting a new token by email
#[utoipa::path(
    post,
    path = "/api/account",
    request_body = Account,
    responses(
        (status = 200, description = "Successfully created account", body=Account),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// POST handler for requesting a new token by email
pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<Account>,
) -> AppResult<(StatusCode, AccountResponse)> {
    let mut accounts = state.accounts.write().unwrap();

    let name = payload.name.to_string();

    if accounts.contains_key(&name) {
        return Ok((
            StatusCode::BAD_REQUEST,
            AccountResponse::BadRequest(Response::new("Account already exists".to_string()).into()),
        ));
    }

    let account = Account::new(payload.name, payload.email, payload.did);
    accounts.insert(name, account.clone());
    Ok((StatusCode::OK, AccountResponse::Created(account.into())))
}
