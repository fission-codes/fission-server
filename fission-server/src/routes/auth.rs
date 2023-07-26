//! Routes for authn/authz

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::email_verification::{self, EmailVerification},
    settings::Settings,
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

/// POST handler for requesting a new token by email
pub async fn request_token(
    State(state): State<AppState>,
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
    use axum::{body::Body, http::Request, Router};

    use fission_core::authority::key_material::generate_ed25519_material;
    use http::StatusCode;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use tokio::sync::broadcast;
    use tower::ServiceExt;
    use ucan::{builder::UcanBuilder, Ucan};

    use crate::{
        error::ErrorResponse,
        routes::auth::VerificationCodeResponse,
        settings::Settings,
        test_utils::{test_context::TestContext, BroadcastVerificationCodeSender},
    };

    #[tokio::test]
    async fn test_request_code_ok() {
        let (tx, mut rx) = broadcast::channel(1);
        let ctx = TestContext::new_with_state(|builder| {
            builder.with_verification_code_sender(BroadcastVerificationCodeSender(tx))
        })
        .await;

        let settings = Settings::load().unwrap();
        let email = "oedipa@trystero.com";

        let issuer = generate_ed25519_material();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(&settings.server().did)
            .with_lifetime(10)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let (status, _) =
            request_verification_code::<VerificationCodeResponse>(ctx.app(), email, Some(ucan))
                .await;

        let (email, _) = rx.recv().await.unwrap();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(email, "oedipa@trystero.com");
    }

    #[tokio::test]
    async fn test_request_code_no_ucan() {
        let ctx = TestContext::new().await;
        let email = "oedipa@trystero.com";

        let (status, _) = request_verification_code::<ErrorResponse>(ctx.app(), email, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_request_code_wrong_aud() {
        let ctx = TestContext::new().await;

        let email = "oedipa@trystero.com";

        let issuer = generate_ed25519_material();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience("did:fission:1234")
            .with_lifetime(10)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let (status, _) =
            request_verification_code::<ErrorResponse>(ctx.app(), email, Some(ucan)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    async fn request_verification_code<T>(
        app: Router,
        email: &str,
        ucan: Option<Ucan>,
    ) -> (StatusCode, T)
    where
        T: DeserializeOwned,
    {
        let builder = Request::builder()
            .method("POST")
            .uri("/api/auth/email/verify")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref());

        let builder = if let Some(ucan) = ucan {
            let token = format!("Bearer {}", ucan.encode().unwrap());

            builder.header(http::header::AUTHORIZATION, token)
        } else {
            builder
        };

        let request = builder
            .body(Body::from(
                serde_json::to_vec(&json!(
                    {
                        "email": email
                    }
                ))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = serde_json::from_slice::<T>(&body).unwrap();

        (status, body)
    }
}
