//! Account routes

use crate::{
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::{
        account::{Account, NewAccount},
        email_verification::EmailVerification,
    },
    router::AppState,
};
use axum::{
    self,
    extract::{Json, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

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

    let mut conn = db::connect(&state.db_pool).await?;

    // let verification_token =
    EmailVerification::find_token(&mut conn, &payload.email, &payload.did, code.unwrap()).await?;

    // FIXME do something with the verification token here.

    Ok((
        StatusCode::OK,
        Json(
            Account::new(&mut conn, payload.username, payload.email, payload.did)
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
    State(state): State<AppState>,
    authority: Authority,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let account = Account::find_by_username(
        &mut db::connect(&state.db_pool).await?,
        authority.ucan,
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
    State(state): State<AppState>,
    authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<Did>,
) -> AppResult<(StatusCode, Json<NewAccount>)> {
    let mut conn = db::connect(&state.db_pool).await?;

    let account = Account::find_by_username(&mut conn, authority.ucan, username).await?;
    let result = account.update_did(&mut conn, payload.did).await?;

    Ok((StatusCode::OK, Json(result.into())))
}
