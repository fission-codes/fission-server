//! Fission Account Routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self, Pool},
    error::{AppError, AppResult},
    models::{
        account::{Account, AccountRequest, RootAccount},
        email_verification::EmailVerification,
    },
};
use axum::{
    self,
    extract::{Json, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

use anyhow::{anyhow, Result};

/// POST handler for creating a new account
#[utoipa::path(
    post,
    path = "/api/account",
    request_body = AccountRequest,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully created account", body=RootAccount),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]

/// POST handler for creating a new account
pub async fn create_account(
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<AccountRequest>,
) -> AppResult<(StatusCode, Json<RootAccount>)> {
    if let Err(err) = find_validation_token(&state.db_pool, &authority, &payload.email).await {
        return Err(AppError::new(StatusCode::FORBIDDEN, Some(err.to_string())));
    }

    // Now create the account!

    let mut conn = db::connect(&state.db_pool).await?;
    let did = authority.ucan.issuer().to_string();
    let new_account = RootAccount::new(&mut conn, payload.username, payload.email, &did).await?;

    Ok((StatusCode::CREATED, Json(new_account)))
}

#[utoipa::path(
    get,
    path = "/api/account/{username}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body=AccountRequest),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account details
pub async fn get_account(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<AccountRequest>)> {
    let account =
        Account::find_by_username(&mut db::connect(&state.db_pool).await?, username.clone())
            .await?;

    Ok((StatusCode::OK, Json(account.into())))
}

/// AccountUpdateRequest Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct AccountUpdateRequest {
    username: String,
    email: String,
}

#[utoipa::path(
    put,
    path = "/api/account/{username}/did",
    request_body = AccountUpdateRequest,
    responses(
        (status = 200, description = "Successfully updated DID", body=AccountRequest),
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
    Json(payload): Json<AccountUpdateRequest>,
) -> AppResult<(StatusCode, Json<RootAccount>)> {
    find_validation_token(&state.db_pool, &authority, &payload.email).await?;

    // Now update the account!

    let mut conn = db::connect(&state.db_pool).await?;

    let account = Account::find_by_username(&mut conn, username).await?;
    let did = authority.ucan.issuer().to_string();

    Ok((
        StatusCode::OK,
        Json(RootAccount::update(&mut conn, &account, &did).await?),
    ))
}

async fn find_validation_token(
    db_pool: &Pool,
    authority: &Authority,
    email: &str,
) -> Result<EmailVerification, anyhow::Error> {
    // Validate Code
    let code = authority
        .ucan
        .facts()
        .iter()
        .filter_map(|f| f.as_object())
        .find_map(|f| {
            f.get("code")
                .and_then(|c| c.as_str())
                .and_then(|c| c.parse::<u64>().ok())
        });

    match code {
        None => Err(anyhow!("Missing validation token")),
        Some(code) => {
            let did = authority.ucan.issuer().to_string();

            let mut conn = db::connect(db_pool).await?;
            // FIXME do something with the verification token here.
            //   - mark it as used
            //   - also above, check expiry
            //   - also above, check that it's not already used

            EmailVerification::find_token(&mut conn, email, &did, code).await
        }
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use http::{Method, StatusCode};
    use serde_json::json;
    use tokio::sync::broadcast;
    use ucan::crypto::KeyMaterial;

    use crate::{
        error::ErrorResponse,
        models::account::RootAccount,
        routes::auth::VerificationCodeResponse,
        test_utils::{
            test_context::TestContext, BroadcastVerificationCodeSender, RouteBuilder, UcanBuilder,
        },
    };

    #[tokio::test]
    async fn test_create_account_ok() -> Result<()> {
        let (tx, mut rx) = broadcast::channel(1);
        let ctx = TestContext::new_with_state(|builder| {
            builder.with_verification_code_sender(BroadcastVerificationCodeSender(tx))
        })
        .await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let (ucan, issuer) = UcanBuilder::default().finalize().await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = rx.recv().await?;

        let (ucan, issuer) = UcanBuilder::default()
            .with_issuer(issuer)
            .with_fact(json!({ "code": code }))?
            .finalize()
            .await?;

        let (status, root_account) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account")
            .with_ucan(ucan)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<RootAccount>()
            .await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(root_account.account.username, username);
        assert_eq!(root_account.account.email, email);
        assert_eq!(root_account.ucan.audience(), issuer.get_did().await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_code() -> Result<()> {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";

        let (ucan, _) = UcanBuilder::default()
            .with_fact(json!({ "code": "wrong code" }))?
            .finalize()
            .await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account")
            .with_ucan(ucan)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_issuer() -> Result<()> {
        let (tx, mut rx) = broadcast::channel(1);
        let ctx = TestContext::new_with_state(|builder| {
            builder.with_verification_code_sender(BroadcastVerificationCodeSender(tx))
        })
        .await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";

        let (ucan, _) = UcanBuilder::default().finalize().await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = rx.recv().await.unwrap();

        let (ucan, _) = UcanBuilder::default()
            .with_fact(json!({ "code": code }))?
            .finalize()
            .await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account")
            .with_ucan(ucan)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        Ok(())
    }
}
