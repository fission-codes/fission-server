use std::sync::{Arc, Mutex};

use crate::traits::VerificationCodeSender;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri};
use hyper::Body;
use mime::{Mime, APPLICATION_JSON};
use rs_ucan::{ucan::Ucan, DefaultFact};
use serde::{de::DeserializeOwned, Serialize};
use tower::ServiceExt;

pub(crate) mod test_context;
pub(crate) mod test_ipfs_database;

pub(crate) struct RouteBuilder<F = DefaultFact> {
    app: Router,
    method: Method,
    path: Uri,
    body: Option<(Mime, Body)>,
    ucan: Option<Ucan<F>>,
    ucan_proof: Option<Ucan>,
    accept_mime: Option<Mime>,
}

impl<F: Clone + DeserializeOwned> RouteBuilder<F> {
    pub(crate) fn new<U>(app: Router, method: Method, path: U) -> Self
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<http::Error>,
    {
        Self {
            app,
            method,
            path: TryFrom::try_from(path).map_err(Into::into).unwrap(),
            body: Default::default(),
            ucan: Default::default(),
            ucan_proof: Default::default(),
            accept_mime: Default::default(),
        }
    }

    pub(crate) fn with_ucan(mut self, ucan: Ucan<F>) -> Self {
        self.ucan = Some(ucan);
        self
    }

    #[allow(unused)]
    pub(crate) fn with_ucan_proof(mut self, ucan: Ucan) -> Self {
        self.ucan_proof = Some(ucan);
        self
    }

    pub(crate) fn with_accept_mime(mut self, accept_mime: Mime) -> Self {
        self.accept_mime = Some(accept_mime);
        self
    }

    pub(crate) fn with_json_body<T>(mut self, body: T) -> Result<Self>
    where
        T: Serialize,
    {
        let body = Body::from(serde_json::to_vec(&body)?);

        self.body = Some((APPLICATION_JSON, body));

        Ok(self)
    }

    pub(crate) async fn into_raw_response(mut self) -> Result<(StatusCode, Bytes)> {
        let request = self.build_request()?;
        let response = self.app.oneshot(request).await?;
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await?;

        Ok((status, body))
    }

    pub(crate) async fn into_json_response<T>(mut self) -> Result<(StatusCode, T)>
    where
        T: DeserializeOwned,
    {
        self.accept_mime = self.accept_mime.or(Some(APPLICATION_JSON));

        let request = self.build_request()?;
        let response = self.app.oneshot(request).await?;
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await?;
        match serde_json::from_slice::<T>(&body) {
            Ok(body) => Ok((status, body)),
            Err(e) => Err(anyhow!(
                "Couldn't parse {}: {e}",
                String::from_utf8_lossy(&body)
            )),
        }
    }

    fn build_request(&mut self) -> Result<Request<Body>> {
        let builder = Request::builder()
            .method(self.method.clone())
            .uri(self.path.clone());

        let builder = if let Some(mime) = self.accept_mime.take() {
            builder.header(http::header::ACCEPT, mime.as_ref())
        } else {
            builder
        };

        let builder = if let Some(ucan) = self.ucan.take() {
            let token = format!("Bearer {}", ucan.encode()?);

            builder.header(http::header::AUTHORIZATION, token)
        } else {
            builder
        };

        let builder = if let Some(proof) = self.ucan_proof.take() {
            let encoded_ucan = proof.encode()?;
            let cid = proof.to_cid(None)?;
            builder.header("ucan", format!("{} {}", cid, encoded_ucan))
        } else {
            builder
        };

        let request = if let Some((mime, body)) = self.body.take() {
            builder
                .header(http::header::CONTENT_TYPE, mime.as_ref())
                .body(body)?
        } else {
            builder.body(Body::from(vec![]))?
        };

        Ok(request)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TestVerificationCodeSender {
    emails: Arc<Mutex<Vec<(String, String)>>>,
}

impl TestVerificationCodeSender {
    pub(crate) fn get_emails(&self) -> Vec<(String, String)> {
        self.emails.lock().unwrap().clone()
    }
}

#[async_trait]
impl VerificationCodeSender for TestVerificationCodeSender {
    async fn send_code(&self, email: &str, code: &str) -> Result<()> {
        self.emails
            .lock()
            .unwrap()
            .push((email.to_string(), code.to_string()));
        Ok(())
    }
}
