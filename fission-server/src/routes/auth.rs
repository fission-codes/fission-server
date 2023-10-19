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

    if !authority.has_capability(
        root_did.clone(),
        EmailAbility::Verify,
        &root_did,
        &DidVerifierMap::default(),
    )? {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            Some("email/verify capability is rooted incorrectly."),
        ));
    }

    request.validate().map_err(|e| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("Invalid request: {e}")),
        )
    })?;

    request.compute_code_hash(root_did.as_ref())?;

    log::debug!(
        "Successfully computed code hash {}",
        request.code_hash.clone().unwrap()
    );

    let mut conn = db::connect(&state.db_pool).await?;

    EmailVerification::new(&mut conn, &request, root_did.as_ref()).await?;

    request.send_code(state.verification_code_sender).await?;

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
        error::{AppError, ErrorResponse},
        models::email_verification::{hash_code, EmailVerification},
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder},
    };
    use anyhow::anyhow;
    use assert_matches::assert_matches;
    use chrono::{Duration, Local};
    use diesel_async::RunQueryDsl;
    use fission_core::{
        capabilities::{did::Did, email::EmailAbility},
        ed_did_key::EdDidKey,
        facts::EmailVerificationFacts,
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
    async fn test_email_verification_fetch_token() -> TestResult {
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

        RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
            .with_ucan(ucan)
            .with_json_body(json!({ "email": email }))?
            .into_json_response::<VerificationCodeResponse>()
            .await?;

        let (_, email_content) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email sent");

        let code = email_content
            .parse()
            .expect("Couldn't parse validation code");

        let token_result = EmailVerification::find_token(
            &mut ctx.get_db_conn().await,
            email,
            &EmailVerificationFacts {
                code,
                did: issuer.did(),
            },
        )
        .await;

        assert_matches!(
            token_result,
            Ok(EmailVerification {
                email, did, ..
            }) if email == "oedipa@trystero.com" && did == issuer.did()
        );

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
    async fn test_request_code_no_ucan() -> TestResult {
        let ctx = TestContext::new().await;
        let email = "oedipa@trystero.com";

        let (status, body) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<ErrorResponse>()
                .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert_matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::UNAUTHORIZED,
                ..
            }]
        );

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

        assert_matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::BAD_REQUEST,
                ..
            }]
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_request_code_expires() -> TestResult {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();
        let code = 123456;

        let inserted_at = Local::now()
            .naive_utc()
            .checked_sub_signed(Duration::hours(25))
            .ok_or_else(|| anyhow!("Couldn't construct old date."))?;

        let record = EmailVerification {
            id: 0,
            inserted_at,
            updated_at: inserted_at,
            did: issuer.did(),
            email: email.to_string(),
            code_hash: hash_code(email, issuer.as_ref(), code),
        };

        diesel::insert_into(email_verifications::table)
            .values(&record)
            .execute(&mut conn)
            .await?;

        let facts = &EmailVerificationFacts {
            code,
            did: issuer.did(),
        };

        let token_result = EmailVerification::find_token(&mut conn, email, &facts).await;

        assert_matches!(token_result, Err(_));

        Ok(())
    }
}
