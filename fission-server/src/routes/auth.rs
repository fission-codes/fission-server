//! Routes for authn/authz

use crate::{
    app_state::AppState,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::EmailVerification,
    setups::{ServerSetup, VerificationCodeSender},
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use fission_core::common::{EmailVerifyRequest, SuccessResponse};
use validator::Validate;

/// POST handler for requesting a new token by email
#[utoipa::path(
    post,
    path = "/api/v0/auth/email/verify",
    request_body = EmailVerifyRequest,
    responses(
        (status = 200, description = "Successfully sent request token", body = SuccessResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 415, description = "Unsupported Media Type"),
        (status = 422, description = "Unprocessable Entity"),
    )
)]
pub async fn request_token<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Json(request): Json<EmailVerifyRequest>,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    request
        .validate()
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(e)))?;

    let mut conn = db::connect(&state.db_pool).await?;

    let verification = EmailVerification::new(&mut conn, &request).await?;

    state
        .verification_code_sender
        .send_code(&verification.email, &verification.code)
        .await?;

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })))
}

#[cfg(test)]
mod tests {
    use crate::{
        db::schema::email_verifications, models::email_verification::EmailVerification,
        routes::auth::SuccessResponse, test_utils::test_context::TestContext,
    };
    use anyhow::{anyhow, Result};
    use assert_matches::assert_matches;
    use chrono::{Duration, Local};
    use diesel_async::RunQueryDsl;
    use fission_core::dns;
    use http::{Method, StatusCode};
    use serde_json::json;
    use testresult::TestResult;

    async fn request_code(email: &str, ctx: &TestContext) -> Result<(StatusCode, String, String)> {
        let (status, _) = ctx
            .request(Method::POST, "/api/v0/auth/email/verify")
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<SuccessResponse>()
            .await?;

        let (email_address, email_code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        Ok((status, email_address, email_code))
    }

    #[test_log::test(tokio::test)]
    async fn test_request_code_ok() -> TestResult {
        let ctx = &TestContext::new().await?;

        let email = "oedipa@trystero.com";

        let (status, email, _) = request_code(email, ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(email, "oedipa@trystero.com");

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_email_verification_fetch_token() -> TestResult {
        let ctx = &TestContext::new().await?;

        let email = "oedipa@trystero.com";

        let (_, _, code) = request_code(email, ctx).await?;

        let token_result =
            EmailVerification::find_token(&mut ctx.get_db_conn().await?, email, &code).await;

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
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let email = "oedipa@trystero.com";
        let code = "123456";

        let inserted_at = Local::now()
            .naive_utc()
            .checked_sub_signed(Duration::try_hours(25).unwrap())
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
            .execute(conn)
            .await?;

        let token_result = EmailVerification::find_token(conn, email, code).await;

        assert_matches!(token_result, Err(_));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_request_code_consumed() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let email = "oedipa@trystero.com";

        let (_, _, code) = request_code(email, ctx).await?;

        let token = EmailVerification::find_token(conn, email, &code).await?;

        assert_eq!(&token.email, email);

        token.consume_token(conn).await?;

        let result = EmailVerification::find_token(conn, email, &code).await;

        assert_matches!(result, Err(_));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_server_did() -> TestResult {
        let ctx = &TestContext::new().await?;

        let (status, response) = ctx
            .request(Method::GET, "/dns-query?name=_did.localhost&type=TXT")
            .with_accept_mime("application/dns-json".parse()?)
            .into_json_response::<dns::Response>()
            .await?;

        assert_eq!(status, StatusCode::OK);

        let answer = response
            .answer
            .into_iter()
            .next()
            .ok_or("Missing DNS answer")?;

        let did = answer.data;

        assert_eq!(did, ctx.app_state().server_keypair.did());

        Ok(())
    }
}
