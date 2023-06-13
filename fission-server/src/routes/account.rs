//! Account routes

use crate::{
    authority::Authority,
    db::{self, Pool},
    error::{AppError, AppResult},
    models::{
        account::{Account, NewAccount},
        email_verification::EmailVerification,
    },
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
    State(pool): State<Pool>,
    authority: Authority,
    Json(payload): Json<NewAccount>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
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
        let request = EmailVerification::find_token(
            db::connect(&pool).await?,
            &payload.email,
            &payload.did,
            code,
        )
        .await;
        if request.is_err() {
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

    let account = Account::new(
        db::connect(&pool).await?,
        payload.username,
        payload.email,
        payload.did,
    )
    .await;

    let account_response = NewAccount {
        username: account.username,
        email: account.email,
        did: account.did,
    };

    Ok((StatusCode::OK, Json(account_response)))
}

#[utoipa::path(
    get,
    path = "/api/account/{name}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body=NewAccount),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account details
pub async fn get_account(
    State(pool): State<Pool>,
    authority: Authority,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    if let Err(err) = authority.validate().await {
        log::debug!("Error validating authority: {}", err);
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            Some("Unauthorized".to_string()),
        ));
    };

    let account = Account::find_by_username_and_did(
        db::connect(&pool).await?,
        username.clone(),
        authority.ucan.issuer().to_string(),
    )
    .await;

    log::debug!("Got user: {}", username.clone());

    if account.is_ok() {
        Ok((StatusCode::OK, Json(account.unwrap().into())))
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
    path = "/api/account/{username}/did",
    responses(
        (status = 200, description = "Successfully updated DID", body=NewAccount),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// Handler to update the DID associated with an account
pub async fn update_did(
    State(pool): State<Pool>,
    authority: Authority,
    Path(name): Path<String>,
    Json(payload): Json<Did>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let account = Account::update_did(
        db::connect(&pool).await?,
        name,
        authority.ucan.issuer().to_string(),
        payload.did,
    )
    .await;

    if account.is_ok() {
        Ok((StatusCode::OK, Json(account.unwrap().into())))
    } else {
        Err(AppError::new(
            StatusCode::NOT_FOUND,
            Some("Account not found".to_string()),
        ))
    }
}
