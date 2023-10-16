//! Routes for authn/authz

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
    traits::ServerSetup,
};
use axum::{
    self,
    extract::{Json, State},
    http::StatusCode,
};
use fission_core::capabilities::{did::Did, email::EmailAbility};
use rs_ucan::{did_verifier::DidVerifierMap, semantics::caveat::EmptyCaveat};
use serde::{Deserialize, Serialize};
use tracing::log;
use utoipa::ToSchema;

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
        (status = 510, description = "Not extended")
    )
)]
pub async fn request_token<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(mut request): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<VerificationCodeResponse>)> {
    let server_did = state.did.as_ref().as_ref();
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

    let root_did = authority
        .ucan
        .capabilities()
        .find_map(|cap| {
            match (
                cap.resource().downcast_ref(),
                cap.ability().downcast_ref(),
                cap.caveat().downcast_ref(),
            ) {
                (Some(Did(did)), Some(EmailAbility::Verify), Some(EmptyCaveat)) => {
                    Some(Did(did.clone()))
                }
                _ => None,
            }
        })
        .ok_or_else(|| {
            AppError::new(
                StatusCode::FORBIDDEN,
                Some("Missing email/verify capability in UCAN."),
            )
        })?;

    let did = root_did.to_string();
    if !authority.has_capability(
        root_did,
        EmailAbility::Verify,
        did.clone(),
        &DidVerifierMap::default(),
    )? {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            Some("email/verify capability is rooted incorrectly."),
        ));
    }

    request.compute_code_hash(&did)?;

    log::debug!(
        "Successfully computed code hash {}",
        request.code_hash.clone().unwrap()
    );

    let mut conn = db::connect(&state.db_pool).await?;

    EmailVerification::new(&mut conn, request.clone(), &did).await?;

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
    use crate::{
        error::{AppError, ErrorResponse},
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder},
    };
    use fission_core::{
        capabilities::{did::Did, email::EmailAbility},
        ed_did_key::EdDidKey,
    };
    use http::{Method, StatusCode};
    use rs_ucan::{
        builder::UcanBuilder, capability::Capability, semantics::caveat::EmptyCaveat, ucan::Ucan,
        DefaultFact,
    };
    use serde_json::json;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_request_code_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                EmailAbility::Verify,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
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

    #[test_log::test(tokio::test)]
    async fn test_request_code_no_capability_err() -> TestResult {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(ctx.server_did())
            .sign(issuer)?;

        let (status, body) =
            RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_ucan(ucan)
                .with_json_body(json!({ "email": email }))?
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

    #[test_log::test(tokio::test)]
    async fn test_request_code_no_ucan() -> TestResult {
        let ctx = TestContext::new().await;
        let email = "oedipa@trystero.com";

        let (status, body) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
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

    #[test_log::test(tokio::test)]
    async fn test_request_code_wrong_aud() -> TestResult {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience("did:fission:1234")
            .sign(issuer)?;

        let (status, body) =
            RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
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
