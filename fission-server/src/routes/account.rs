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

    use axum::{body::Body, http::Request, Router};

    use fission_core::authority::key_material::generate_ed25519_material;
    use http::StatusCode;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use tokio::sync::broadcast;
    use tower::ServiceExt;
    use ucan::{builder::UcanBuilder, crypto::KeyMaterial};

    use crate::{
        error::ErrorResponse,
        models::account::RootAccount,
        routes::auth::VerificationCodeResponse,
        settings::Settings,
        test_utils::{test_context::TestContext, BroadcastVerificationCodeSender},
    };

    #[tokio::test]
    async fn test_create_account_ok() {
        let (tx, mut rx) = broadcast::channel(1);
        let ctx = TestContext::new_with_state(|builder| {
            builder.with_verification_code_sender(BroadcastVerificationCodeSender(tx))
        })
        .await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let settings = Settings::load().unwrap();
        let issuer = generate_ed25519_material();
        let audience = &settings.server().did;

        let (status, _) = request_verification_code::<VerificationCodeResponse, _>(
            ctx.app(),
            email,
            &issuer,
            audience,
        )
        .await;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = rx.recv().await.unwrap();
        let (status, root_account) =
            create_account::<RootAccount, _>(ctx.app(), username, email, &code, &issuer, audience)
                .await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(root_account.account.username, username);
        assert_eq!(root_account.account.email, email);
        assert_eq!(
            root_account.ucan.audience(),
            issuer.get_did().await.unwrap()
        );
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_code() {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let settings = Settings::load().unwrap();
        let issuer = generate_ed25519_material();
        let audience = &settings.server().did;

        let (status, _) = create_account::<ErrorResponse, _>(
            ctx.app(),
            username,
            email,
            "code",
            &issuer,
            audience,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_issuer() {
        let (tx, mut rx) = broadcast::channel(1);
        let ctx = TestContext::new_with_state(|builder| {
            builder.with_verification_code_sender(BroadcastVerificationCodeSender(tx))
        })
        .await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let settings = Settings::load().unwrap();
        let issuer1 = generate_ed25519_material();
        let issuer2 = generate_ed25519_material();
        let audience = &settings.server().did;

        let (status, _) = request_verification_code::<VerificationCodeResponse, _>(
            ctx.app(),
            email,
            &issuer1,
            audience,
        )
        .await;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = rx.recv().await.unwrap();
        let (status, _) = create_account::<ErrorResponse, _>(
            ctx.app(),
            username,
            email,
            &code,
            &issuer2,
            audience,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    async fn request_verification_code<T, K>(
        app: Router,
        email: &str,
        issuer: &K,
        audience: &str,
    ) -> (StatusCode, T)
    where
        T: DeserializeOwned,
        K: KeyMaterial,
    {
        let ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(audience)
            .with_lifetime(10)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = format!("Bearer {}", ucan.encode().unwrap());

        let request = Request::builder()
            .method("POST")
            .uri("/api/auth/email/verify")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::AUTHORIZATION, token)
            .body(Body::from(
                serde_json::to_vec(&json!(
                    {
                        "email": email
                    }
                ))
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = serde_json::from_slice::<T>(&body).unwrap();

        (status, body)
    }

    async fn create_account<T, K>(
        app: Router,
        username: &str,
        email: &str,
        code: &str,
        issuer: &K,
        audience: &str,
    ) -> (StatusCode, T)
    where
        T: DeserializeOwned,
        K: KeyMaterial,
    {
        let ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(audience)
            .with_lifetime(10)
            .with_fact(json!({ "code": code }))
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let token = format!("Bearer {}", ucan.encode().unwrap());

        let request = Request::builder()
            .method("POST")
            .uri("/api/account")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::AUTHORIZATION, token)
            .body(Body::from(
                serde_json::to_vec(&json!(
                    {
                        "username": username,
                        "email": email
                    }
                ))
                .unwrap(),
            ))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = serde_json::from_slice::<T>(&body).unwrap();

        (status, body)
    }
}
