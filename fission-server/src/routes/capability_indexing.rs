//! Routes for the capability indexing endpoints

use crate::{
    app_state::AppState, authority::Authority, db, error::AppResult, extract::json::Json,
    models::capability_indexing::find_ucans_for_audience, setups::ServerSetup,
};
use axum::extract::State;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::{
    capabilities::{did::Did, indexing::IndexingAbility},
    common::UcansResponse,
};
use http::StatusCode;

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
    let Did(audience_needle) = authority
        .get_capability(&state, IndexingAbility::Fetch)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let ucans = find_ucans_for_audience(audience_needle, conn).await?;

            Ok((StatusCode::OK, Json(ucans)))
        }
        .scope_boxed()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::Conn, error::ErrorResponse, models::capability_indexing::index_ucan,
        test_utils::test_context::TestContext,
    };
    use anyhow::Result;
    use assert_matches::assert_matches;
    use fission_core::ed_did_key::EdDidKey;
    use http::Method;
    use rs_ucan::{
        builder::UcanBuilder,
        capability::Capability,
        semantics::{ability::TopAbility, caveat::EmptyCaveat},
        ucan::Ucan,
    };
    use testresult::TestResult;

    async fn index_test_ucan(
        issuer: &EdDidKey,
        audience: &EdDidKey,
        resource_did: String,
        conn: &mut Conn<'_>,
    ) -> Result<Ucan> {
        let ucan: Ucan = UcanBuilder::default()
            .for_audience(audience)
            .claiming_capability(Capability::new(Did(resource_did), TopAbility, EmptyCaveat))
            .sign(issuer)?;

        index_ucan(&ucan, conn).await?;

        Ok(ucan)
    }

    async fn fetch_capabilities(
        requestor: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, UcansResponse)> {
        let auth: Ucan = UcanBuilder::default()
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(requestor.did()),
                IndexingAbility::Fetch,
                EmptyCaveat,
            ))
            .sign(requestor)?;

        let (status, response) = ctx
            .request(Method::GET, "/api/v0/capabilities")
            .with_ucan(auth)
            .into_json_response::<UcansResponse>()
            .await?;

        Ok((status, response))
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_ok() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let device = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan = index_test_ucan(server, device, server.did(), conn).await?;

        let (status, response) = fetch_capabilities(device, ctx).await?;
        assert_eq!(status, StatusCode::OK);

        let ucans = response.ucans.values().into_iter().collect::<Vec<_>>();
        assert_matches!(&ucans[..], [one_ucan] if one_ucan.encode().unwrap() == ucan.encode().unwrap());

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_unauthorized() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let device = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(device)
            .claiming_capability(Capability::new(Did(server.did()), TopAbility, EmptyCaveat))
            .sign(server)?;

        index_ucan(&ucan, conn).await?;

        let (status, _) = ctx
            .request(Method::GET, "/api/v0/capabilities")
            .into_json_response::<ErrorResponse>()
            .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_filtered_by_audience() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let device = &EdDidKey::generate();
        let device_other = &EdDidKey::generate();
        let server = ctx.server_did();

        // Index a test UCAN from `server` -> `device_other`
        let ucan_other = index_test_ucan(server, device_other, server.did(), conn).await?;
        // Requesting UCANs delegated to `device` should end up empty
        let (status, response) = fetch_capabilities(device, ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert!(response.ucans.is_empty());

        // Index a test UCAN from `server` -> `device` this time
        let ucan = index_test_ucan(server, device, server.did(), conn).await?;

        // Requesting UCANs should only return the ones that end in the relevant issuer's DID
        let (_, response) = fetch_capabilities(device, ctx).await?;
        let (_, response_other) = fetch_capabilities(device_other, ctx).await?;

        let ucans = response.ucans.into_values().into_iter().collect::<Vec<_>>();
        let ucans_other = response_other
            .ucans
            .into_values()
            .into_iter()
            .collect::<Vec<_>>();
        assert_matches!(&ucans[..], [u] if u.encode().unwrap() == ucan.encode().unwrap());
        assert_matches!(&ucans_other[..], [u] if u.encode().unwrap() == ucan_other.encode().unwrap());

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_capabilities_fetches_whole_chain() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let id_one = &EdDidKey::generate();
        let id_two = &EdDidKey::generate();
        let server = ctx.server_did();

        let ucan_one = index_test_ucan(server, id_one, server.did(), conn).await?;
        let ucan_two = index_test_ucan(id_one, id_two, server.did(), conn).await?;

        let (status, response) = fetch_capabilities(id_two, ctx).await?;

        assert_eq!(status, StatusCode::OK);

        // We currently allow it to fetch the whole chain, ignoring
        // the `prf` UCAN field altogether.
        // In the future, when the `prf` field is removed, this will make
        // a lot more sense.

        let ucans = response
            .ucans
            .into_values()
            .into_iter()
            .map(|ucan| ucan.encode())
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(ucans.len(), 2);
        assert!(ucans.contains(&ucan_one.encode()?));
        assert!(ucans.contains(&ucan_two.encode()?));

        Ok(())
    }
}
