//! Account routes

use crate::{
    authority::Authority,
    error::{AppError, AppResult},
    models::{account::NewAccount, email_verification},
    router::AppState,
};
use axum::{
    self,
    extract::{Json, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use tracing::log;
use utoipa::ToSchema;

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
    NewAccount(NewAccount),
    /// Error
    Error(Message),
}

/// POST handler for creating a new account
#[utoipa::path(
    post,
    path = "/api/account",
    request_body = NewAccount,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully created account", body=NewAccount),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// POST handler for creating a new account
pub async fn create_account(
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<NewAccount>,
) -> AppResult<(StatusCode, Json<Response>)> {
    let request_tokens = state.request_tokens.read().await;

    if !request_tokens.contains_key(&payload.email) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(Response::Error(Message::new(
                "Invalid request token".to_string(),
            ))),
        ));
    }

    let request = request_tokens.get(&payload.email).unwrap();

    let code = authority
        .ucan
        .facts()
        .iter()
        .filter(|f| f.as_object().is_some())
        .map(|f| f.as_object().unwrap().clone())
        .filter(|f| f.contains_key("code"))
        .find_map(|f| f["code"].as_u64());

    if code.is_some() {
        let computed_hash =
            email_verification::hash_code(&payload.email, authority.ucan.issuer(), code.unwrap());
        if computed_hash != request.code_hash.clone().unwrap() {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(Response::Error(Message::new(
                    "Invalid validation token".to_string(),
                ))),
            ));
        }
    } else {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Missing validation token".to_string()),
        ));
    }

    let mut accounts = state.accounts.write().await;

    let username = payload.username.to_string();

    if accounts.contains_key(&username) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(Response::Error(Message::new(
                "Account already exists".to_string(),
            ))),
        ));
    }

    let account = NewAccount::new(payload.username, payload.email, payload.did);
    accounts.insert(username, account.clone());
    Ok((StatusCode::OK, Json(Response::NewAccount(account))))
}

#[utoipa::path(
    get,
    path = "/api/account/{name}",
    responses(
        (status = 200, description = "Found account", body=NewAccount),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account details
pub async fn get_account(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let accounts = state.accounts.read().await;

    log::info!("name: {}", name);

    if let Some(account) = accounts.get(&name) {
        Ok((StatusCode::OK, Json(account.clone())))
    } else {
        Err(AppError::new(
            StatusCode::NOT_FOUND,
            Some("Account not found".to_string()),
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
    put,
    path = "/api/account/{name}/did",
    responses(
        (status = 200, description = "Successfully updated DID", body=NewAccount),
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
    let mut accounts = state.accounts.write().await;

    if let Some(account) = accounts.get_mut(&name) {
        account.did = payload.did;
        Ok((StatusCode::OK, Json(Response::NewAccount(account.clone()))))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(Response::Error(Message::new(
                "Account not found".to_string(),
            ))),
        ))
    }
}
