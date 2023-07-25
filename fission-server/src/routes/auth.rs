//! Generic ping route.

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
pub struct Response {
    msg: String,
}

impl Response {
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
        (status = 429, description = "Too many requests"),
        (status = 500, description = "Internal Server Error", body=AppError),
        (status = 510, description = "Not extended")
    )
)]

/// POST handler for requesting a new token by email
pub async fn request_token(
    State(state): State<AppState>,
    authority: Authority,
    Json(payload): Json<email_verification::Request>,
) -> AppResult<(StatusCode, Json<Response>)> {
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
        Json(Response::new("Successfully sent request token".to_string())),
    ))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};

    use fission_core::authority::key_material::generate_ed25519_material;
    use http::StatusCode;
    use serde_json::json;
    use tokio::sync::broadcast;
    use tower::ServiceExt;
    use ucan::{builder::UcanBuilder, Ucan};

    use crate::{
        app_state::AppState,
        router::setup_app_router,
        routes::auth::Response,
        settings::Settings,
        test_utils::{test_context::TestContext, BroadcastVerificationCodeSender},
    };

    #[tokio::test]
    async fn test_request_code_ok() {
        let settings = Settings::load().unwrap();

        let (tx, mut rx) = broadcast::channel(1);

        let ctx = TestContext::new();
        let app_state = AppState {
            verification_code_sender: Box::new(BroadcastVerificationCodeSender(tx)),
            ..ctx.app_state().await
        };

        let app = setup_app_router(app_state);

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

        let token = format!("Bearer {}", ucan.encode().unwrap());

        let request = Request::builder()
            .method("POST")
            .uri("/api/auth/email/verify")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(http::header::AUTHORIZATION, token)
            .body(Body::from(
                serde_json::to_vec(&json!(
                    {
                        "email": "oedipa@trystero.com"
                    }
                ))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        let (email, _) = rx.recv().await.unwrap();

        assert_eq!(email, "oedipa@trystero.com");
        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = serde_json::from_slice::<Response>(&body);

        assert!(matches!(body, Ok(_)));
    }

    #[tokio::test]
    async fn test_request_code_no_ucan() {
        assert_request_code_err(None, StatusCode::UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn test_request_code_wrong_aud() {
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

        assert_request_code_err(Some(ucan), StatusCode::BAD_REQUEST).await;
    }

    async fn assert_request_code_err(ucan: Option<Ucan>, status_code: StatusCode) {
        let ctx = TestContext::new();
        let app_state = ctx.app_state().await;
        let app = setup_app_router(app_state);

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
                        "email": "oedipa@trystero.com"
                    }
                ))
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), status_code);
    }
}
