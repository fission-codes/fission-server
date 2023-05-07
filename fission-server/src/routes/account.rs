//! Account routes

use crate::{error::AppResult, router::AppState};
use axum::{
    self,
    extract::{Json, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

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

/// Message Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Message {
    msg: String,
}

impl Message {
    /// Create a new instance of [Message]
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// Response Enum
#[derive(Debug, Serialize)]
pub enum Response {
    /// Account created
    Account(Account),
    /// Error
    Error(Message),
}

/// POST handler for creating a new account
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

/// POST handler for creating a new account
pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<Account>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let mut accounts = state.accounts.write().unwrap();

    let name = payload.name.to_string();

    if accounts.contains_key(&name) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(Response::Error(Message::new(
                "Account already exists".to_string(),
            ))),
        ));
    }

    let account = Account::new(payload.name, payload.email, payload.did);
    accounts.insert(name, account.clone());
    Ok((StatusCode::OK, Json(Response::Account(account))))
}

#[utoipa::path(
    get,
    path = "/api/account/:name",
    responses(
        (status = 200, description = "Found account", body=Account),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account details
pub async fn get_account(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let accounts = state.accounts.read().unwrap();

    if let Some(account) = accounts.get(&name) {
        Ok((StatusCode::OK, Json(Response::Account(account.clone()))))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(Response::Error(Message::new(
                "Account not found".to_string(),
            ))),
        ))
    }
}

/// DID Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Did {
    name: String,
    did: String,
}

#[utoipa::path(
    post,
    path = "/api/account/:name/did",
    responses(
        (status = 200, description = "Successfully updated DID", body=Account),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// Handler to update the DID associated with an account
pub async fn update_did(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<Did>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let mut accounts = state.accounts.write().unwrap();

    if let Some(account) = accounts.get_mut(&name) {
        account.did = payload.did;
        Ok((StatusCode::OK, Json(Response::Account(account.clone()))))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(Response::Error(Message::new(
                "Account not found".to_string(),
            ))),
        ))
    }
}
