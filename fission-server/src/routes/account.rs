//! Fission Account Routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self, Pool},
    error::{AppError, AppResult},
    models::{
        account::{Account, AccountRequest, RootAccount},
        email_verification::{EmailVerification, VerificationCode},
    },
    traits::ServerSetup,
};
use anyhow::{anyhow, Result};
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
    path = "/api/v0/account",
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
pub async fn create_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority<VerificationCode>,
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

/// GET handler to retrieve account details
#[utoipa::path(
    get,
    path = "/api/v0/account/{username}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body=AccountRequest),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
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

/// Handler to update the DID associated with an account
#[utoipa::path(
    put,
    path = "/api/v0/account/{username}/did",
    request_body = AccountUpdateRequest,
    responses(
        (status = 200, description = "Successfully updated DID", body=AccountRequest),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn update_did<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority<VerificationCode>,
    Path(username): Path<String>,
    Json(payload): Json<AccountUpdateRequest>,
) -> AppResult<(StatusCode, Json<RootAccount>)> {
    if let Err(err) = find_validation_token(&state.db_pool, &authority, &payload.email).await {
        return Err(AppError::new(StatusCode::FORBIDDEN, Some(err.to_string())));
    }

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
    authority: &Authority<VerificationCode>,
    email: &str,
) -> Result<EmailVerification, anyhow::Error> {
    // Validate Code
    let code = authority
        .ucan
        .facts()
        .ok_or_else(|| anyhow!("Missing or malformed validation token"))?;

    let did = authority.ucan.issuer().to_string();

    let mut conn = db::connect(db_pool).await?;
    // FIXME do something with the verification token here.
    //   - mark it as used
    //   - also above, check expiry
    //   - also above, check that it's not already used

    EmailVerification::find_token(&mut conn, email, &did, code).await
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};
    use rs_ucan::{builder::UcanBuilder, ucan::Ucan, DefaultFact};
    use serde_json::json;

    use crate::{
        authority::generate_ed25519_issuer,
        db::schema::accounts,
        error::{AppError, ErrorResponse},
        models::{
            account::{AccountRequest, RootAccount},
            email_verification::VerificationCode,
        },
        routes::auth::VerificationCodeResponse,
        settings::Settings,
        test_utils::{test_context::TestContext, RouteBuilder},
    };

    #[tokio::test]
    async fn test_create_account_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let server_did = Settings::load()?.server().did.clone();

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let (issuer, key) = generate_ed25519_issuer();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .sign(&key)?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email Sent");

        let ucan2 = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .with_fact(VerificationCode {
                code: code.parse()?,
            })
            .sign(&key)?;

        let (status, root_account) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan2)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<RootAccount>()
            .await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(root_account.account.username, username);
        assert_eq!(root_account.account.email, email);
        assert_eq!(root_account.ucan.audience(), issuer);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_code() -> Result<()> {
        let ctx = TestContext::new().await;

        let server_did = Settings::load()?.server().did.clone();

        let username = "oedipa";
        let email = "oedipa@trystero.com";

        let (issuer, key) = generate_ed25519_issuer();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .with_fact(VerificationCode { code: 1_000_000 }) // wrong code
            .sign(&key)?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::FORBIDDEN,
                ..
            }]
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_create_account_err_wrong_issuer() -> Result<()> {
        let ctx = TestContext::new().await;

        let server_did = Settings::load()?.server().did.clone();

        let username = "oedipa";
        let email = "oedipa@trystero.com";

        let (issuer, key) = generate_ed25519_issuer();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .sign(&key)?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        let (wrong_issuer, wrong_key) = generate_ed25519_issuer();
        let ucan = UcanBuilder::default()
            .issued_by(&wrong_issuer)
            .for_audience(&server_did)
            .with_fact(VerificationCode {
                code: code.parse()?,
            })
            .sign(&wrong_key)?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({ "username": username, "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::FORBIDDEN,
                ..
            }]
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_account_ok() -> Result<()> {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
            ))
            .execute(&mut conn)
            .await?;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/api/v0/account/{}", username),
        )
        .into_json_response::<AccountRequest>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.username, username);
        assert_eq!(body.email, email);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_account_err_not_found() -> Result<()> {
        let ctx = TestContext::new().await;
        let username = "donnie";

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/api/v0/account/{}", username),
        )
        .into_json_response::<ErrorResponse>()
        .await?;

        assert_eq!(status, StatusCode::NOT_FOUND);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::NOT_FOUND,
                ..
            }]
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_put_account_did_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let server_did = Settings::load()?.server().did.clone();

        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
            ))
            .execute(&mut conn)
            .await?;

        let (issuer, key) = generate_ed25519_issuer();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .sign(&key)?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .with_fact(VerificationCode {
                code: code.parse()?,
            })
            .sign(&key)?;

        let (status, body) = RouteBuilder::new(
            ctx.app(),
            Method::PUT,
            format!("/api/v0/account/{}/did", username),
        )
        .with_ucan(ucan)
        .with_json_body(json!({ "username": username, "email": email }))?
        .into_json_response::<RootAccount>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.account.username, username);
        assert_eq!(body.account.email, email);
        assert_eq!(body.ucan.audience(), issuer);

        Ok(())
    }

    #[tokio::test]
    async fn test_put_account_did_err_wrong_code() -> Result<()> {
        let ctx = TestContext::new().await;

        let server_did = Settings::load()?.server().did.clone();

        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
            ))
            .execute(&mut conn)
            .await?;

        let (issuer, key) = generate_ed25519_issuer();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&server_did)
            .with_fact(VerificationCode {
                code: 1_000_000, // wrong code
            })
            .sign(&key)?;

        let (status, body) = RouteBuilder::new(
            ctx.app(),
            Method::PUT,
            format!("/api/v0/account/{}/did", username),
        )
        .with_ucan(ucan)
        .with_json_body(json!({ "username": username, "email": email }))?
        .into_json_response::<ErrorResponse>()
        .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::FORBIDDEN,
                ..
            }]
        ));

        Ok(())
    }
}
