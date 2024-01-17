//! Fission Account Routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self, schema::accounts},
    error::{AppError, AppResult},
    extract::{
        doh::{encode_query_as_request, DnsQuery},
        json::Json,
    },
    models::{
        account::{AccountAndAuth, AccountRecord},
        email_verification::EmailVerification,
        revocation::NewRevocationRecord,
    },
    setups::ServerSetup,
};
use anyhow::{anyhow, Result};
use axum::{
    self,
    extract::{Path, State},
    http::StatusCode,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection, RunQueryDsl};
use fission_core::{
    capabilities::{did::Did, fission::FissionAbility},
    common::{Account, AccountCreationRequest, AccountLinkRequest, DidResponse, SuccessResponse},
    ed_did_key::EdDidKey,
    revocation::Revocation,
    username::{Handle, Username},
};
use hickory_server::proto::{rr::RecordType, serialize::binary::BinDecodable};
use rs_ucan::ucan::Ucan;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
};
use tracing::debug;
use validator::Validate;

/// POST handler for creating a new account
#[utoipa::path(
    post,
    path = "/api/v0/account",
    request_body = AccountCreationRequest,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully created account", body = AccountAndAuth),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn create_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(request): Json<AccountCreationRequest>,
) -> AppResult<(StatusCode, Json<AccountAndAuth>)> {
    request
        .validate()
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(e)))?;

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountCreate)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let verification = EmailVerification::find_token(conn, &request.email, &request.code)
                .await
                .map_err(|err| AppError::new(StatusCode::FORBIDDEN, Some(err.to_string())))?;

            debug!("Found EmailVerification {verification:?}");

            let new_account = AccountAndAuth::new(
                request.username,
                verification.email.to_string(),
                &did,
                state.server_keypair.as_ref(),
                &state.dns_settings,
                conn,
            )
            .await?;

            verification.consume_token(conn).await?;

            Ok((StatusCode::CREATED, Json(new_account)))
        }
        .scope_boxed()
    })
    .await
}

/// POST handler for linking a DID to an existing account via email challenge
#[utoipa::path(
    post,
    path = "/api/v0/account/{did}/link",
    request_body = AccountLinkRequest,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully linked account", body = AccountAndAuth),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 422, description = "Unprocessable entity"),
    )
)]
pub async fn link_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(account_did): Path<String>,
    authority: Authority,
    Json(request): Json<AccountLinkRequest>,
) -> AppResult<(StatusCode, Json<AccountAndAuth>)> {
    let Did(agent_did) = authority
        .get_capability(&state, FissionAbility::AccountLink)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let account: AccountRecord = accounts::dsl::accounts
                .filter(accounts::did.eq(account_did))
                .first(conn)
                .await?;

            let email = account.email.clone().ok_or(AppError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                Some("No email address associated"),
            ))?;

            let verification = EmailVerification::find_token(conn, &email, &request.code)
                .await
                .map_err(|err| AppError::new(StatusCode::FORBIDDEN, Some(err.to_string())))?;

            debug!("Found EmailVerification {verification:?}");

            let account = AccountAndAuth::link_agent(
                account,
                &agent_did,
                &state.server_keypair,
                &state.dns_settings,
                conn,
            )
            .await?;

            verification.consume_token(conn).await?;

            Ok((StatusCode::OK, Json(account)))
        }
        .scope_boxed()
    })
    .await
}

/// GET handler to retrieve account details
#[utoipa::path(
    get,
    path = "/api/v0/account/{did}",
    responses(
        (status = 200, description = "Found account", body = Account),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(did): Path<String>,
) -> AppResult<(StatusCode, Json<Account>)> {
    let conn = &mut db::connect(&state.db_pool).await?;

    let account: AccountRecord = accounts::dsl::accounts
        .filter(accounts::did.eq(did))
        .first(conn)
        .await?;

    let account = account.to_account(&state.dns_settings)?;

    Ok((StatusCode::OK, Json(account)))
}

/// GET handler to retrieve account details
#[utoipa::path(
    get,
    path = "/api/v0/account/{username}/did",
    responses(
        (status = 200, description = "Found account", body = DidResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_did<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<DidResponse>)> {
    let conn = &mut db::connect(&state.db_pool).await?;

    let account: AccountRecord = accounts::dsl::accounts
        .filter(accounts::username.eq(&username))
        .first(conn)
        .await?;

    Ok((StatusCode::OK, Json(DidResponse { did: account.did })))
}

/// PATCH Handler for changing the username
#[utoipa::path(
    patch,
    path = "/api/v0/account/username/{username}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Updated account", body = SuccessResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 429, description = "Conflict"),
    )
)]
pub async fn patch_username<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    // Validate the handle as a username
    Username::from_str(&username)?;

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;

    // conflicts are handled via the `impl From<diesel::result::Error> for AppError`
    use crate::db::schema::*;
    diesel::update(accounts::table)
        .filter(accounts::did.eq(&did))
        .set(accounts::username.eq(&username))
        .execute(conn)
        .await?;

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })))
}

/// PATCH Handler for changing the account handle
#[utoipa::path(
    patch,
    path = "/api/v0/account/handle/{handle}",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Updated account", body = SuccessResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 429, description = "Conflict"),
    )
)]
pub async fn patch_handle<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(handle): Path<Handle>,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    // Validate the handle is a valid DNS name
    handle.validate()?;

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    // TODO Better APIs. It should be easier to ask our own DNS server some Qs
    let localhost_dns_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));

    let message_bytes = state
        .dns_server
        .answer_request(encode_query_as_request(
            DnsQuery::new(format!("_did.{handle}"), RecordType::TXT),
            localhost_dns_v4,
        )?)
        .await?;

    let message = hickory_server::proto::op::Message::from_bytes(message_bytes.as_ref())
        .map_err(|e| anyhow!(e))?;

    let response = fission_core::dns::Response::from_message(message)?;

    let record = response
        .answer
        .iter()
        .find(|answer| answer.data == did)
        .ok_or(AppError::new(
            StatusCode::FORBIDDEN,
            Some(format!(
                "Couldn't find DNS TXT record for _did.{handle} set to {did}"
            )),
        ))?;

    tracing::info!(?record, "Found DNS record. Changing handle.");

    let conn = &mut db::connect(&state.db_pool).await?;

    // conflicts are handled via the `impl From<diesel::result::Error> for AppError`
    use crate::db::schema::*;
    diesel::update(accounts::table)
        .filter(accounts::did.eq(&did))
        .set(accounts::handle.eq(handle.as_str()))
        .execute(conn)
        .await?;

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })))
}

/// DELETE Handler for removing domain name association
#[utoipa::path(
    delete,
    path = "/api/v0/account/handle",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Updated account", body = SuccessResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn delete_handle<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;

    use crate::db::schema::*;
    diesel::update(accounts::table)
        .filter(accounts::did.eq(&did))
        .set(accounts::handle.eq(&None::<String>))
        .execute(conn)
        .await?;

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })))
}

/// Handler for deleting an account
#[utoipa::path(
    delete,
    path = "/api/v0/account",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Deleted", body = Account),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn delete_account<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
) -> AppResult<(StatusCode, Json<Account>)> {
    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountDelete)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    let server_keypair = state.server_keypair;
    conn.transaction(|conn| {
        async move {
            use crate::db::schema::{accounts, capabilities, ucans, revocations};
            let account = diesel::delete(accounts::table)
                .filter(accounts::did.eq(&did))
                .get_result::<AccountRecord>(conn)
                .await
                .optional()?
                .ok_or_else(|| {
                    AppError::new(
                        StatusCode::NOT_FOUND,
                        Some("Couldn't find an account with this DID."),
                    )
                })?;

            let indexed_ucans: Vec<(String, String, i32)> = capabilities::table
                .inner_join(ucans::table)
                .filter(capabilities::resource.eq(&did))
                .select((ucans::issuer, ucans::encoded, ucans::id))
                .get_results(conn)
                .await?;

            let ucan_ids = indexed_ucans.iter().map(|(_, _, ucan_id)| ucan_id);

            // Revoke the server to user UCANs

            fn ucan_revocation(issuer: &EdDidKey, encoded_ucan: &str) -> Result<NewRevocationRecord> {
                let ucan: Ucan = Ucan::from_str(encoded_ucan)?;
                let revocation = Revocation::new(issuer, &ucan)?;
                Ok(NewRevocationRecord::new(revocation))
            }

            let revocation_records = indexed_ucans
                .iter()
                .filter(|(issuer, _, _)| (issuer == server_keypair.did_as_str()))
                .map(|(_, encoded, _)| ucan_revocation(&server_keypair, encoded))
                .collect::<Result<Vec<NewRevocationRecord>>>()?;

            if revocation_records.is_empty() {
                tracing::warn!(?account, "Trouble revoking UCANs associated with this account: Couldn't find UCANs to revoke");
            }

            diesel::insert_into(revocations::table)
                .values(revocation_records)
                .execute(conn).await?;

            // We also delete any revoked ucans, since we don't need them anymore & they're a liability data-wise.
            diesel::delete(ucans::table)
                .filter(ucans::id.eq_any(ucan_ids))
                .execute(conn)
                .await?;

            Ok((StatusCode::OK, Json(account.to_account(&state.dns_settings)?)))
        }
        .scope_boxed()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::schema::accounts,
        error::{AppError, ErrorResponse},
        models::account::AccountAndAuth,
        test_utils::{route_builder::RouteBuilder, test_context::TestContext},
    };
    use anyhow::{bail, Result};
    use assert_matches::assert_matches;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use fission_core::{capabilities::did::Did, common::SuccessResponse, ed_did_key::EdDidKey};
    use http::{Method, StatusCode};
    use rs_ucan::{
        builder::UcanBuilder, capability::Capability, semantics::caveat::EmptyCaveat, ucan::Ucan,
        DefaultFact,
    };
    use serde::de::DeserializeOwned;
    use serde_json::{json, Value};
    use testresult::TestResult;

    async fn create_account<T: DeserializeOwned>(
        username: &str,
        email: &str,
        issuer: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, T)> {
        let (status, response) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<SuccessResponse>()
                .await?;

        assert_eq!(status, StatusCode::OK);
        assert!(response.success);

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email Sent");

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountCreate,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, root_account) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({
                "username": username,
                "email": email,
                "code": code,
            }))?
            .into_json_response::<T>()
            .await?;

        Ok((status, root_account))
    }

    async fn link_account<T: DeserializeOwned>(
        account_did: &str,
        email: &str,
        issuer: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, T)> {
        let (status, response) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<SuccessResponse>()
                .await?;

        assert_eq!(status, StatusCode::OK);
        assert!(response.success);

        let (_, code) = ctx
            .verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email Sent");

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountLink,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, root_account) = RouteBuilder::new(
            ctx.app(),
            Method::POST,
            &format!("/api/v0/account/{account_did}/link"),
        )
        .with_ucan(ucan)
        .with_json_body(json!({ "code": code }))?
        .into_json_response::<T>()
        .await?;

        Ok((status, root_account))
    }

    fn build_acc_invocation(
        ability: FissionAbility,
        account: &AccountAndAuth,
        issuer: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<Ucan> {
        let account_ucan = account
            .ucans
            .iter()
            .find(|ucan| ucan.audience() == issuer.did_as_str());

        let Some(account_ucan) = account_ucan else {
            bail!("Missing Ucan!");
        };
        let Some(account_did) = account_ucan
            .capabilities()
            .find_map(|cap| cap.resource().downcast_ref::<Did>())
        else {
            bail!("Missing account capability");
        };

        assert_eq!(account_did.to_string(), account.account.did);

        let invocation = UcanBuilder::default()
            .claiming_capability(Capability::new(account_did.clone(), ability, EmptyCaveat))
            .for_audience(ctx.server_did())
            .witnessed_by(account_ucan, None)
            .sign(issuer)?;

        Ok(invocation)
    }

    async fn patch_username<T: DeserializeOwned>(
        new_username: &str,
        account: &AccountAndAuth,
        issuer: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, T)> {
        let invocation =
            build_acc_invocation(FissionAbility::AccountManage, &account, issuer, ctx)?;

        RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::PATCH,
            format!("/api/v0/account/username/{new_username}"),
        )
        .with_ucan(invocation)
        .with_ucan_proofs(account.ucans.clone())
        .into_json_response()
        .await
    }

    async fn delete_account<T: DeserializeOwned>(
        account: &AccountAndAuth,
        issuer: &EdDidKey,
        ctx: &TestContext,
    ) -> Result<(StatusCode, T)> {
        let invocation = build_acc_invocation(FissionAbility::AccountDelete, account, issuer, ctx)?;
        RouteBuilder::<DefaultFact>::new(ctx.app(), Method::DELETE, format!("/api/v0/account"))
            .with_ucan(invocation)
            .with_ucan_proofs(account.ucans.clone())
            .into_json_response()
            .await
    }

    #[test_log::test(tokio::test)]
    async fn test_create_account_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, root_account) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            root_account.account.username,
            Some(ctx.user_handle(username))
        );
        assert_eq!(root_account.account.email, Some(email.to_string()));
        assert!(root_account
            .ucans
            .iter()
            .any(|ucan| ucan.audience() == issuer.as_ref()));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_create_account_same_username_conflict() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, _) = create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);

        let username = "oedipa";
        let email = "oedipa2@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, err) = create_account::<Value>(username, email, issuer, &ctx).await?;

        tracing::error!(?err, "Response");

        assert_eq!(status, StatusCode::CONFLICT);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_create_account_err_wrong_code() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, _) =
            RouteBuilder::<DefaultFact>::new(ctx.app(), Method::POST, "/api/v0/auth/email/verify")
                .with_json_body(json!({ "email": email }))?
                .into_json_response::<SuccessResponse>()
                .await?;

        assert_eq!(status, StatusCode::OK);

        ctx.verification_code_sender()
            .get_emails()
            .into_iter()
            .last()
            .expect("No email Sent");

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(ctx.server_did())
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountCreate,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::POST, "/api/v0/account")
            .with_ucan(ucan)
            .with_json_body(json!({
                "username": username,
                "email": email,
                "code": "1000000", // wrong code
            }))?
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
    async fn test_get_account_ok() -> TestResult {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
            ))
            .execute(&mut conn)
            .await?;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/api/v0/account/{did}"),
        )
        .into_json_response::<Account>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.username, Some(ctx.user_handle(username)));
        assert_eq!(body.email, Some(email.to_string()));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_account_err_not_found() -> TestResult {
        let ctx = TestContext::new().await;
        let username = "donnie";

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/api/v0/account/{username}"),
        )
        .into_json_response::<ErrorResponse>()
        .await?;

        assert_eq!(status, StatusCode::NOT_FOUND);

        assert_matches!(
            body.errors.as_slice(),
            [AppError {
                status: StatusCode::NOT_FOUND,
                ..
            }]
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_account_did_by_username() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let issuer = &EdDidKey::generate();

        let (_, account) = create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        let (_, response) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/api/v0/account/{username}/did"),
        )
        .into_json_response::<DidResponse>()
        .await?;

        assert_eq!(response.did, account.account.did);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_patch_account_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let username2 = "oedipa2";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, root_account) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            root_account.account.username,
            Some(ctx.user_handle(username))
        );
        assert_eq!(root_account.account.email, Some(email.to_string()));

        let (status, resp) =
            patch_username::<SuccessResponse>(username2, &root_account, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert!(resp.success);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_delete_account_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, root_account) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            root_account.account.username,
            Some(ctx.user_handle(username))
        );
        assert_eq!(root_account.account.email, Some(email.to_string()));

        let (status, account) = delete_account::<Account>(&root_account, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(account.username, root_account.account.username);
        assert_eq!(account.email, root_account.account.email);
        assert_eq!(account.did, root_account.account.did);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_patch_revoked_account_err() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let username2 = "oedipa2";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, root_account) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            root_account.account.username,
            Some(ctx.user_handle(username))
        );
        assert_eq!(root_account.account.email, Some(email.to_string()));

        let (status, account) = delete_account::<Account>(&root_account, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(account.username, root_account.account.username);
        assert_eq!(account.email, root_account.account.email);
        assert_eq!(account.did, root_account.account.did);

        let (status, _) =
            patch_username::<serde_json::Value>(username2, &root_account, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_account_link_ok() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, response) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);

        let issuer2 = &EdDidKey::generate();

        let (status, link_response) =
            link_account::<AccountAndAuth>(&response.account.did, email, issuer2, &ctx).await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(link_response.account.did, response.account.did);
        assert_eq!(link_response.account.email, Some(email.to_string()));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_account_link_unknown_did_not_found() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, _) = create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);

        let issuer2 = &EdDidKey::generate();

        let (status, _) =
            link_account::<Value>(EdDidKey::generate().did_as_str(), email, issuer2, &ctx).await?;

        assert_eq!(status, StatusCode::NOT_FOUND);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_account_link_wrong_email_forbidden() -> TestResult {
        let ctx = TestContext::new().await;

        let username = "oedipa";
        let email = "oedipa@trystero.com";
        let issuer = &EdDidKey::generate();

        let (status, response) =
            create_account::<AccountAndAuth>(username, email, issuer, &ctx).await?;

        assert_eq!(status, StatusCode::CREATED);

        let issuer2 = &EdDidKey::generate();
        let email2 = "someone.else@trystero.com";

        let (status, _) =
            link_account::<Value>(&response.account.did, email2, issuer2, &ctx).await?;

        assert_eq!(status, StatusCode::FORBIDDEN);

        Ok(())
    }
}
