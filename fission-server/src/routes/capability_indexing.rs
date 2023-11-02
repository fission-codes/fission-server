//! Routes for the capability indexing endpoints

use axum::extract::State;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::{
    capabilities::{did::Did, indexing::IndexingAbility},
    common::UcansResponse,
};
use http::StatusCode;

use crate::{
    app_state::AppState,
    authority::Authority,
    db,
    error::{AppError, AppResult},
    extract::json::Json,
    models::capability_indexing::find_ucans_for_audience,
    traits::ServerSetup,
};

/// Return capabilities for a given DID
#[utoipa::path(
    get,
    path = "/api/v0/capabilities",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body = UcansResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_capabilities<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
) -> AppResult<(StatusCode, Json<UcansResponse>)> {
    let Did(audience_needle) = authority.get_capability(IndexingAbility::Fetch)?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let ucans = find_ucans_for_audience(audience_needle, conn)
                .await
                .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, Some(e)))?;

            Ok((StatusCode::OK, Json(UcansResponse { ucans })))
        }
        .scope_boxed()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::Conn,
        error::ErrorResponse,
        models::capability_indexing::index_ucan,
        test_utils::{test_context::TestContext, RouteBuilder},
    };
    use anyhow::Result;
    use assert_matches::assert_matches;
    use fission_core::{capabilities::did::Did, ed_did_key::EdDidKey};
    use http::Method;
    use rs_ucan::{
        builder::UcanBuilder,
        capability::Capability,
        semantics::{ability::TopAbility, caveat::EmptyCaveat},
        ucan::Ucan,
        DefaultFact,
    };
    use testresult::TestResult;

    async fn index_test_ucan(
        issuer: &EdDidKey,
        audience: &EdDidKey,
        conn: &mut Conn<'_>,
    ) -> Result<Ucan> {
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience(audience)
            .claiming_capability(Capability::new(Did(issuer.did()), TopAbility, EmptyCaveat))
            .sign(issuer)?;

        index_ucan(&ucan, conn).await?;

        Ok(ucan)
    }

    async fn fetch_capabilities(
        requestor: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, UcansResponse)> {
        let auth: Ucan = UcanBuilder::default()
            .issued_by(requestor)
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(requestor.did()),
                IndexingAbility::Fetch,
                EmptyCaveat,
            ))
            .sign(requestor)?;

        let (status, response) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::GET, "/api/v0/capabilities")
                .with_ucan(auth)
                .into_json_response::<UcansResponse>()
                .await?;

        Ok((status, response))
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_ok() -> TestResult {
        let ctx = TestContext::new().await;
        let conn = &mut ctx.get_db_conn().await;

        let device = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan = index_test_ucan(server, device, conn).await?;

        let (status, response) = fetch_capabilities(device, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert_matches!(&response.ucans[..], [one_ucan] if one_ucan.encode().unwrap() == ucan.encode().unwrap());

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_unauthorized() -> TestResult {
        let ctx = TestContext::new().await;
        let conn = &mut ctx.get_db_conn().await;

        let device = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan: Ucan = UcanBuilder::default()
            .issued_by(server)
            .for_audience(device)
            .claiming_capability(Capability::new(Did(server.did()), TopAbility, EmptyCaveat))
            .sign(server)?;

        index_ucan(&ucan, conn).await?;

        let (status, _) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::GET, "/api/v0/capabilities")
                .into_json_response::<ErrorResponse>()
                .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_filtered_by_audience() -> TestResult {
        let ctx = TestContext::new().await;
        let conn = &mut ctx.get_db_conn().await;

        let device = &EdDidKey::generate();
        let device_other = &EdDidKey::generate();
        let server = ctx.server_did();

        // Index a test UCAN from `server` -> `device_other`
        let ucan_other = index_test_ucan(server, device_other, conn).await?;
        // Requesting UCANs delegated to `device` should end up empty
        let (status, response) = fetch_capabilities(device, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert!(response.ucans.is_empty());

        // Index a test UCAN from `server` -> `device` this time
        let ucan = index_test_ucan(server, device, conn).await?;

        // Requesting UCANs should only return the ones that end in the relevant issuer's DID
        let (_, response) = fetch_capabilities(device, &ctx).await?;
        let (_, response_other) = fetch_capabilities(device_other, &ctx).await?;

        assert_matches!(&response.ucans[..], [u] if u.encode().unwrap() == ucan.encode().unwrap());
        assert_matches!(&response_other.ucans[..], [u] if u.encode().unwrap() == ucan_other.encode().unwrap());

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_fetches_whole_chain() -> TestResult {
        let ctx = TestContext::new().await;
        let conn = &mut ctx.get_db_conn().await;

        let id_one = &EdDidKey::generate();
        let id_two = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan_one = index_test_ucan(server, id_one, conn).await?;
        let ucan_two = index_test_ucan(id_one, id_two, conn).await?;

        let (status, response) = fetch_capabilities(id_two, &ctx).await?;

        // We currently allow it to fetch the whole chain, ignoring
        // the `prf` UCAN field altogether.
        // In the future, when the `prf` field is removed, this will make
        // a lot more sense.
        assert_eq!(status, StatusCode::OK);
        assert_matches!(
            &response.ucans[..],
            [u1, u2] if
                u1.encode().unwrap() == ucan_one.encode().unwrap()
                && u2.encode().unwrap() == ucan_two.encode().unwrap()
        );

        Ok(())
    }
}
