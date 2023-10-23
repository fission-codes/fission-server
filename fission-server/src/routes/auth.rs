//! Routes for authn/authz

use crate::{
    app_state::AppState,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
    traits::{ServerSetup, VerificationCodeSender},
};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Response for Request Token
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VerificationCodeResponse {
    msg: String,
}

impl VerificationCodeResponse {
    /// Create a new Response
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// POST handler for requesting a new token by email
#[utoipa::path(
    post,
    path = "/api/v0/auth/email/verify",
    request_body = email_verification::Request,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully sent request token", body = VerificationCodeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 415, description = "Unsupported Media Type"),
        (status = 422, description = "Unprocessable Entity"),
    )
)]
pub async fn request_token<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Json(request): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<VerificationCodeResponse>)> {
    request
        .validate()
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(e)))?;

    let mut conn = db::connect(&state.db_pool).await?;

    let verification = EmailVerification::new(&mut conn, &request).await?;

    state
        .verification_code_sender
        .send_code(&verification.email, &verification.code)
        .await?;

    Ok((
        StatusCode::OK,
        Json(VerificationCodeResponse::new(
            "Successfully sent request token".to_string(),
        )),
    ))
}

/// GET handler for the server's current DID
/// TODO: Keep this? Replace with DoH & DNS?
#[utoipa::path(
    get,
    path = "/api/v0/server-did",
    responses(
        (status = 200, description = "Responds with the server DID in the body", body = String),
    )
)]
pub async fn server_did<S: ServerSetup>(State(state): State<AppState<S>>) -> String {
    state.did.did()
}

#[cfg(test)]
mod tests {
    use crate::{
        db::schema::email_verifications,
        models::email_verification::EmailVerification,
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder},
    };
    use anyhow::anyhow;
    use assert_matches::assert_matches;
    use chrono::{Duration, Local};
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};
    use rs_ucan::DefaultFact;
    use serde_json::json;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_request_code_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";

        let (status, _) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<VerificationCodeResponse>()
                .await?;

        let (email, _) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(email, "oedipa@trystero.com");

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_email_verification_fetch_token() -> TestResult {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";

        RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        let token_result =
            EmailVerification::find_token(&mut ctx.get_db_conn().await, email, &code).await;

        assert_matches!(
            token_result,
            Ok(EmailVerification {
                email, ..
            }) if email == "oedipa@trystero.com"
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_request_code_expires() -> TestResult {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let email = "oedipa@trystero.com";
        let code = "123456";

        let inserted_at = Local::now()
            .naive_utc()
            .checked_sub_signed(Duration::hours(25))
            .ok_or_else(|| anyhow!("Couldn't construct old date."))?;

        let record = EmailVerification {
            id: 0,
            inserted_at,
            updated_at: inserted_at,
            email: email.to_string(),
            code: code.to_string(),
        };

        diesel::insert_into(email_verifications::table)
            .values(&record)
            .execute(&mut conn)
            .await?;

        let token_result = EmailVerification::find_token(&mut conn, email, code).await;

        assert_matches!(token_result, Err(_));

        Ok(())
    }
}
