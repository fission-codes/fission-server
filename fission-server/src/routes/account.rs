//! Fission Account Routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self, schema::accounts},
    error::{AppError, AppResult},
    extract::json::Json,
    models::{
        account::{Account, RootAccount},
        email_verification::EmailVerification,
    },
    traits::ServerSetup,
};
use axum::{
    self,
    extract::{Path, State},
    http::StatusCode,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection, RunQueryDsl};
use fission_core::capabilities::{did::Did, fission::FissionAbility};
use serde::{Deserialize, Serialize};
use tracing::debug;
use utoipa::ToSchema;
use validator::Validate;

/// Account Request Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema, Validate)]
pub struct AccountCreationRequest {
    /// Username associated with the account
    pub username: String,
    /// Email address associated with the account
    #[validate(email)]
    pub email: String,
    /// Email verification code
    pub code: String,
}

/// Information about an account
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct AccountResponse {
    /// username, if associated
    pub username: Option<String>,
    /// email, if associated
    pub email: Option<String>,
}

/// Information about the DID of an account
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct DidResponse {
    /// The DID of this account
    pub did: String,
}

/// POST handler for creating a new account
#[utoipa::path(
    post,
    path = "/api/v0/account",
    request_body = AccountCreationRequest,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully created account", body = RootAccount),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn create_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(request): Json<AccountCreationRequest>,
) -> AppResult<(StatusCode, Json<RootAccount>)> {
    request
        .validate()
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(e)))?;

    let Did(did) = authority
        .get_capability(FissionAbility::AccountCreate)
        .map_err(|e| AppError::new(StatusCode::FORBIDDEN, Some(e)))?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let verification = EmailVerification::find_token(conn, &request.email, &request.code)
                .await
                .map_err(|err| AppError::new(StatusCode::FORBIDDEN, Some(err.to_string())))?;

            debug!("Found EmailVerification {verification:?}");

            let new_account = RootAccount::new(
                conn,
                request.username,
                verification.email.to_string(),
                &did,
                state.did.as_ref(),
            )
            .await?;

            verification.consume_token(conn).await?;

            Ok((StatusCode::CREATED, Json(new_account)))
        }
        .scope_boxed()
    })
    .await
}

/// GET handler to retrieve account details
#[utoipa::path(
    get,
    path = "/api/v0/account/{username}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body = AccountResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(did): Path<String>,
) -> AppResult<(StatusCode, Json<AccountResponse>)> {
    let conn = &mut db::connect(&state.db_pool).await?;

    let account: Account = accounts::dsl::accounts
        .filter(accounts::did.eq(did))
        .first(conn)
        .await?;

    Ok((
        StatusCode::OK,
        Json(AccountResponse {
            username: account.username,
            email: account.email,
        }),
    ))
}

/// GET handler to retrieve account details
#[utoipa::path(
    get,
    path = "/api/v0/account/{username}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body = DidResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_did<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<DidResponse>)> {
    let conn = &mut db::connect(&state.db_pool).await?;

    let account: Account = accounts::dsl::accounts
        .filter(accounts::username.eq(username))
        .first(conn)
        .await?;

    Ok((StatusCode::OK, Json(DidResponse { did: account.did })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::schema::accounts,
        error::{AppError, ErrorResponse},
        models::account::RootAccount,
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder},
    };
    use assert_matches::assert_matches;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use fission_core::{capabilities::did::Did, ed_did_key::EdDidKey};
    use http::{Method, StatusCode};
    use rs_ucan::{
        builder::UcanBuilder, capability::Capability, semantics::caveat::EmptyCaveat, ucan::Ucan,
        DefaultFact,
    };
    use serde_json::json;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_create_account_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, _) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
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

        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountCreate,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, root_account) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({
                "username": username,
                "email": email,
                "code": code,
            }))?
            .into_json_response::<RootAccount>()
            .await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(root_account.account.username, Some(username.to_string()));
        assert_eq!(root_account.account.email, Some(email.to_string()));
        assert!(root_account
            .ucans
            .iter()
            .any(|ucan| ucan.audience() == issuer.as_ref()));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_create_account_err_wrong_code() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, _) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<VerificationCodeResponse>()
                .await?;

        assert_eq!(status, StatusCode::OK);

        ctx.verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email Sent");

        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountCreate,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({
                "username": username,
                "email": email,
                "code": "1000000", // wrong code
            }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        assert_matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::FORBIDDEN,
                ..
            }]
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_account_ok() -> TestResult {
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
            format!("/api/v0/account/{}", did),
        )
        .into_json_response::<AccountResponse>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.username, Some(username.to_string()));
        assert_eq!(body.email, Some(email.to_string()));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_account_err_not_found() -> TestResult {
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

        assert_matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::NOT_FOUND,
                ..
            }]
        );

        Ok(())
    }
}
