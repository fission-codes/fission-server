//! Account routes

use std::sync::Arc;

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

use tokio::sync::Mutex;
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

    if code.is_none() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Missing validation token".to_string()),
        ));
    }

    let conn = Arc::new(Mutex::new(db::connect(&pool).await?));

    // let verification_token =
    EmailVerification::find_token(conn.clone(), &payload.email, &payload.did, code.unwrap())
        .await?;

    // FIXME do something with the verification token here.

    Ok((
        StatusCode::OK,
        Json(
            Account::new(conn.clone(), payload.username, payload.email, payload.did)
                .await?
                .into(),
        ),
    ))
}

#[utoipa::path(
    get,
    path = "/api/account/{username}",
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
    let account = Account::find_by_username(
        Arc::new(Mutex::new(db::connect(&pool).await?)),
        Some(authority.ucan),
        username.clone(),
    )
    .await?;

    Ok((StatusCode::OK, Json(account.into())))
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
    Path(username): Path<String>,
    Json(payload): Json<Did>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let conn = Arc::new(Mutex::new(db::connect(&pool).await?));

    let account =
        Account::find_by_username(Arc::clone(&conn), Some(authority.ucan), username).await?;

    let result = account.update_did(Arc::clone(&conn), payload.did).await?;
    Ok((StatusCode::OK, Json(result.into())))
}
