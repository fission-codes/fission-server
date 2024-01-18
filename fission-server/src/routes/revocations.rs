//! Routes for UCAN revocation

use crate::{
    app_state::AppState, authority::Authority, db, error::AppResult, extract::json::Json,
    models::revocation::NewRevocationRecord, setups::ServerSetup,
};
use axum::extract::State;
use fission_core::{common::SuccessResponse, revocation::Revocation};
use http::StatusCode;

/// POST handler for adding a UCAN revocation
#[utoipa::path(
    post,
    path = "/api/v0/revocations",
    request_body = Revocation,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully revoked UCAN", body = SuccessResponse),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn post_revocation<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(revocation): Json<Revocation>,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    authority.validate_revocation(&revocation)?;

    let conn = &mut db::connect(&state.db_pool).await?;
    NewRevocationRecord::new(revocation).insert(conn).await?;

    Ok((StatusCode::CREATED, Json(SuccessResponse { success: true })))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{route_builder::RouteBuilder, test_context::TestContext};
    use fission_core::{
        capabilities::{did::Did, fission::FissionAbility},
        common::SuccessResponse,
        ed_did_key::EdDidKey,
        revocation::Revocation,
    };
    use http::{Method, StatusCode};
    use rs_ucan::{
        builder::UcanBuilder, capability::Capability, semantics::caveat::EmptyCaveat, ucan::Ucan,
        DefaultFact,
    };
    use serde_json::Value;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_post_revocation_ok() -> TestResult {
        let ctx = &TestContext::new().await?;

        let issuer = &EdDidKey::generate();

        let ucan: Ucan = UcanBuilder::default()
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountInfo,
                EmptyCaveat,
            ))
            .for_audience("did:web:someone.malicious.com")
            .sign(issuer)?;

        let revocation = Revocation::new(issuer, &ucan)?;

        let (status, response) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/revocations")
                .with_json_body(&revocation)?
                .with_ucan(ucan)
                .into_json_response::<SuccessResponse>()
                .await?;

        assert_eq!(status, StatusCode::CREATED);
        assert!(response.success);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_post_revocation_of_foreign_forbidden() -> TestResult {
        let ctx = &TestContext::new().await?;

        let issuer = &EdDidKey::generate();
        let foreign = &EdDidKey::generate();

        let ucan: Ucan = UcanBuilder::default()
            .claiming_capability(Capability::new(
                Did(foreign.did()),
                FissionAbility::AccountInfo,
                EmptyCaveat,
            ))
            .for_audience("did:web:someone")
            .sign(foreign)?;

        let revocation = Revocation::new(issuer, &ucan)?;

        let (status, _response) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/revocations")
                .with_json_body(&revocation)?
                .with_ucan(ucan)
                .into_json_response::<Value>()
                .await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        Ok(())
    }
}
