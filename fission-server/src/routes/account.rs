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
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// POST handler for creating a new account
pub async fn create_account(
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<NewAccount>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let request_tokens = state.request_tokens.read().await;

    if !request_tokens.contains_key(&payload.email) {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Invalid request token".to_string()),
        ));
    }

    let request = request_tokens.get(&payload.email).unwrap();

    let code = authority
        .ucan
        .facts()
        .iter()
        .filter_map(|f| f.as_object())
        .filter_map(|f| {
            f.get("code")
                .and_then(|c| c.as_str())
                .and_then(|c| c.parse::<u64>().ok())
        })
        .next();

    if let Some(code) = code {
        let computed_hash =
            email_verification::hash_code(&payload.email, authority.ucan.issuer(), code);
        if computed_hash != request.code_hash.clone().unwrap() {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                Some("Invalid validation token".to_string()),
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
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Account already exists".to_string()),
        ));
    }

    let account = NewAccount::new(payload.username, payload.email, payload.did);
    accounts.insert(username, account.clone());

    Ok((StatusCode::OK, Json(account)))
}

#[utoipa::path(
    get,
    path = "/api/account/{name}",
    responses(
        (status = 200, description = "Found account", body=NewAccount),
        (status = 400, description = "Invalid request", body=AppError),
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
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// Handler to update the DID associated with an account
pub async fn update_did(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<Did>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let mut accounts = state.accounts.write().await;

    if let Some(account) = accounts.get_mut(&name) {
        account.did = payload.did;
        Ok((StatusCode::OK, Json(account.clone())))
    } else {
        Err(AppError::new(
            StatusCode::NOT_FOUND,
            Some("Account not found".to_string()),
        ))
    }
}
