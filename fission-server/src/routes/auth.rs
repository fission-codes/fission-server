//! Routes for authn/authz

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
    settings::Settings,
    traits::ServerSetup,
};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

use tracing::log;

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
    path = "/api/auth/email/verify",
    request_body = email_verification::Request,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully sent request token", body=Response),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 510, description = "Not extended")
    )
)]
pub async fn request_token<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(payload): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<VerificationCodeResponse>)> {
    /*

    The age-old question, should this be an invocation, or is the REST endpoint enough here?

    For now, we're using regular UCANs. This check can be done within the authority extractor,
    but we're going to repeat ourselves for now until we're sure that we don't need different
    audiences for different methods.

    */

    let settings = Settings::load();
    if let Err(error) = settings {
        log::error!("Failed to load settings: {}", error);
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Internal Server Error."),
        ));
    }

    let server_did = settings.unwrap().server().did.clone();
    let ucan_aud = authority.ucan.audience();
    if ucan_aud != server_did {
        log::debug!(
            "Incorrect UCAN `aud` used. Expected {}, got {}.",
            server_did,
            ucan_aud
        );
        let error_msg = format!(
            "Authorization UCAN must delegate to this server's DID (expected {}, got {})",
            server_did, ucan_aud
        );
        return Err(AppError::new(StatusCode::BAD_REQUEST, Some(error_msg)));
    }

    let mut request = payload.clone();
    let did = authority.ucan.issuer();
    request.compute_code_hash(did)?;

    log::debug!(
        "Successfully computed code hash {}",
        request.code_hash.clone().unwrap()
    );

    let mut conn = db::connect(&state.db_pool).await?;

    EmailVerification::new(&mut conn, request.clone(), did).await?;

    request.send_code(state.verification_code_sender).await?;

    Ok((
        StatusCode::OK,
        Json(VerificationCodeResponse::new(
            "Successfully sent request token".to_string(),
        )),
    ))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use http::{Method, StatusCode};
    use serde_json::json;

    use crate::{
        error::{AppError, ErrorResponse},
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder, UcanBuilder},
    };

    #[tokio::test]
    async fn test_request_code_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";
        let (ucan, _) = UcanBuilder::default().finalize().await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/auth/email/verify")
            .with_ucan(ucan)
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

    #[tokio::test]
    async fn test_request_code_no_ucan() -> Result<()> {
        let ctx = TestContext::new().await;
        let email = "oedipa@trystero.com";

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/auth/email/verify")
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::UNAUTHORIZED,
                ..
            }]
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_request_code_wrong_aud() -> Result<()> {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";
        let (ucan, _) = UcanBuilder::default()
            .with_audience("did:fission:1234".to_string())
            .finalize()
            .await?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert!(matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::BAD_REQUEST,
                ..
            }]
        ));

        Ok(())
    }
}
