//! Authority extractor
//!
//! Todo: this should be extracted to a separate crate and made available as a generic Axum UCAN extractor.

use crate::{authority::Authority, error::AppError};
use anyhow::anyhow;
use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization, Header, HeaderName},
    http::request::Parts,
    RequestPartsExt,
};
use fission_core::authority::{
    self,
    Error::{InvalidUcan, MissingCredentials},
};
use http::{HeaderValue, StatusCode};
use libipld::Ipld;
use serde_json::json;
use ucan::{
    ability::{arguments::Named, command::ToCommand, parse::ParseAbility},
    Delegation,
};

/////////////////
// UCAN header //
/////////////////

/// The `ucans` header
#[derive(Debug)]
pub struct UcansHeader(Vec<Delegation>);

impl Header for UcansHeader {
    fn name() -> &'static HeaderName {
        static UCAN_HEADER: HeaderName = HeaderName::from_static("ucans");
        static UCAN_HEADER_NAME: &HeaderName = &UCAN_HEADER;
        UCAN_HEADER_NAME
    }

    fn decode<'i, I>(header_values: &mut I) -> Result<UcansHeader, headers::Error>
    where
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let mut delegations = Vec::new();

        for header_value in header_values {
            let header_str = header_value.to_str().map_err(|_| {
                tracing::error!("Got non-string ucan request header: {:?}", header_value);
                headers::Error::invalid()
            })?;

            for ucan_str in header_str.split(',') {
                let ucan_str = ucan_str.trim();
                if ucan_str.is_empty() {
                    // This can be the case, since `"".split(",").collect() == vec![""]`.
                    // Also catches cases where someone sets `ucans=,,<token>` or uses trailing commas.
                    // Per Postel's principle we're lenient in what we accept.
                    continue;
                }

                let bytes = data_encoding::BASE64URL_NOPAD
                    .decode(ucan_str.as_bytes())
                    .map_err(|e| {
                        tracing::error!(
                            ?ucan_str,
                            "Got invalid ucan in ucan request header: {e:#?}"
                        );
                        headers::Error::invalid()
                    })?;

                let delegation: Delegation =
                    serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
                        tracing::error!(
                            ?ucan_str,
                            "Got invalid ucan in ucan request header, couldn't deserialize: {e:#?}"
                        );
                        headers::Error::invalid()
                    })?;

                delegations.push(delegation);
            }
        }

        Ok(UcansHeader(delegations))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let header_str = self
            .0
            .iter()
            .filter_map(|delegation| {
                let result = (|| {
                    let bytes = serde_ipld_dagcbor::to_vec(&delegation)?;
                    let string = data_encoding::BASE64URL_NOPAD.encode(&bytes);
                    Ok::<_, anyhow::Error>(string)
                })();
                if let Err(e) = &result {
                    tracing::error!("Couldn't encode delegation in HTTP header: {e:#?}");
                }
                // This isn't ideal, but avoids panicking.
                result.ok()
            })
            .collect::<Vec<_>>()
            .join(" ");

        match HeaderValue::from_str(&header_str) {
            Err(e) => {
                tracing::error!("Couldn't encode 'ucans' header as string: {e:#?}");
            }
            Ok(header_value) => {
                values.extend([header_value]);
            }
        }
    }
}

////////////
// TRAITS //
////////////

#[async_trait]
impl<S, A> FromRequestParts<S> for Authority<A>
where
    S: Send + Sync,
    A: Clone + ToCommand + ParseAbility,
    Named<Ipld>: From<A>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        do_extract_authority(parts).await.map_err(|err| {
            tracing::error!(?err, "Couldn't extract UCANs from request");
            match err {
                authority::Error::InsufficientCapabilityScope { .. } => {
                    AppError::new(StatusCode::FORBIDDEN, Some("Insufficient capability scope"))
                }
                authority::Error::InvalidUcan { reason } => AppError::new(
                    StatusCode::UNAUTHORIZED,
                    Some(format!("Invalid UCAN: {reason}")),
                ),
                authority::Error::MissingCredentials => {
                    AppError::new(StatusCode::UNAUTHORIZED, Some("Missing credentials"))
                }
                authority::Error::MissingProofs { proofs_needed } => AppError::new(
                    StatusCode::NOT_EXTENDED,
                    Some(json!({ "prf": proofs_needed })),
                ),
            }
        })
    }
}

async fn do_extract_authority<A: Clone + ToCommand + ParseAbility>(
    parts: &mut Parts,
) -> Result<Authority<A>, authority::Error>
where
    Named<Ipld>: From<A>,
{
    // Extract the token from the authorization header
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|e| {
            tracing::error!(?e, "Error while looking up bearer token header value");
            MissingCredentials
        })?;

    let TypedHeader(UcansHeader(delegations)) = parts
        .extract::<TypedHeader<UcansHeader>>()
        .await
        .map_err(|e| {
        tracing::error!(?e, "Error while looking up ucans header value");
        MissingCredentials
    })?;

    // Decode the UCAN
    let token = bearer.token();
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(token.as_bytes())
        .map_err(|e| InvalidUcan {
            reason: anyhow!("Couldn't parse base64 {token:?}: {e:#?}"),
        })?;

    let invocation = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| InvalidUcan {
        reason: anyhow!("Couldn't decode invocation: {e:#?}"),
    })?;

    // Construct authority
    Ok(Authority {
        invocation,
        delegations,
    })
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app_state::AppState, setups::test::TestSetup, test_utils::test_context::TestContext,
    };
    use axum::{
        body::BoxBody,
        extract::State,
        routing::{get, Router},
    };
    use fission_core::caps::{CmdCapabilityFetch, FissionAbility};
    use http::{Request, Response};
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use testresult::TestResult;
    use tower::ServiceExt;
    use ucan::{
        ability::crud::{self, Crud},
        crypto::{
            signature::Envelope,
            varsig::{self, header::EdDsaHeader},
            Nonce,
        },
        did::preset::{Signer, Verifier},
        invocation::Payload,
        Invocation,
    };

    #[test_log::test(tokio::test)]
    async fn extract_authority() -> TestResult {
        let ctx = &TestContext::new().await?;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let did = Verifier::Key(ucan::did::key::Verifier::EdDsa(sk.verifying_key()));
        let signer = Signer::Key(ucan::did::key::Signer::EdDsa(sk));

        let server_did = Verifier::Key(ucan::did::key::Verifier::EdDsa(
            ctx.server_did().verifying_key(),
        ));

        // Test if request requires a valid UCAN
        #[axum_macros::debug_handler]
        async fn authorized_get(
            _state: State<AppState<TestSetup>>,
            _authority: Authority,
        ) -> Response<BoxBody> {
            Response::default()
        }

        let app: Router = Router::new()
            .route("/", get(authorized_get))
            .with_state(ctx.app_state().clone());

        // If a valid UCAN is given
        let ucan = Invocation::try_sign(
            &signer,
            varsig::header::Preset::EdDsa(EdDsaHeader {
                codec: varsig::encoding::Preset::DagCbor,
            }),
            Payload {
                subject: did.clone(),
                issuer: did,
                audience: Some(server_did),
                ability: FissionAbility::CapabilityFetch(CmdCapabilityFetch),
                proofs: Vec::new(),
                cause: None,
                metadata: BTreeMap::new(),
                nonce: Nonce::generate_12(&mut Vec::new()),
                issued_at: None,
                expiration: None,
            },
        )?;

        let ucan_string: String =
            data_encoding::BASE64URL_NOPAD.encode(&serde_ipld_dagcbor::to_vec(&ucan)?);
        let authed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", ucan_string))
                    .body("".into())?,
            )
            .await?;

        assert_eq!(authed.status(), StatusCode::OK);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn extract_authority_no_auth_header() -> TestResult {
        let ctx = &TestContext::new().await?;

        // Test if request requires a valid UCAN
        async fn authorized_get(
            _state: State<AppState<TestSetup>>,
            _authority: Authority,
        ) -> Response<BoxBody> {
            Response::default()
        }

        let app: Router = Router::new()
            .route("/", get(authorized_get))
            .with_state(ctx.app_state().clone());

        // If no authorization header is provided
        let not_authed = app
            .oneshot(Request::builder().uri("/").body("".into()).unwrap())
            .await?;

        assert_eq!(not_authed.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
