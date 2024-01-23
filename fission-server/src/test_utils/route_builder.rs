//! Helpers for running requests
use anyhow::{anyhow, Result};
use axum::Router;
use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri};
use hyper::Body;
use mime::{Mime, APPLICATION_JSON};
use rs_ucan::{ucan::Ucan, DefaultFact};
use serde::{de::DeserializeOwned, Serialize};
use tower::ServiceExt;

#[derive(Debug)]
pub struct RouteBuilder<F = DefaultFact> {
    app: Router,
    method: Method,
    path: Uri,
    body: Option<(Mime, Body)>,
    ucan: Option<Ucan<F>>,
    ucan_proofs: Vec<Ucan>,
    accept_mime: Option<Mime>,
}

impl<F: Clone + DeserializeOwned> RouteBuilder<F> {
    pub fn new<U>(app: Router, method: Method, path: U) -> Self
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
            ucan_proofs: Default::default(),
            accept_mime: Default::default(),
        }
    }

    pub fn with_ucan(mut self, ucan: Ucan<F>) -> Self {
        self.ucan = Some(ucan);
        self
    }

    pub fn with_ucan_proof(mut self, ucan: Ucan) -> Self {
        self.ucan_proofs.extend(Some(ucan));
        self
    }

    pub fn with_ucan_proofs(mut self, proofs: impl IntoIterator<Item = Ucan>) -> Self {
        for proof in proofs.into_iter() {
            self = self.with_ucan_proof(proof);
        }
        self
    }

    pub fn with_accept_mime(mut self, accept_mime: Mime) -> Self {
        self.accept_mime = Some(accept_mime);
        self
    }

    pub fn with_json_body<T>(mut self, body: T) -> Result<Self>
    where
        T: Serialize,
    {
        let body = Body::from(serde_json::to_vec(&body)?);

        self.body = Some((APPLICATION_JSON, body));

        Ok(self)
    }

    pub async fn into_raw_response(mut self) -> Result<(StatusCode, Bytes)> {
        let request = self.build_request()?;
        let response = self.app.oneshot(request).await?;
        let status = response.status();
        let body = hyper::body::to_bytes(response.into_body()).await?;

        Ok((status, body))
    }

    pub async fn into_json_response<T>(mut self) -> Result<(StatusCode, T)>
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
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(self.path.clone());

        if let Some(mime) = self.accept_mime.take() {
            builder = builder.header(http::header::ACCEPT, mime.as_ref())
        }

        if let Some(ucan) = self.ucan.take() {
            let token = format!("Bearer {}", ucan.encode()?);

            builder = builder.header(http::header::AUTHORIZATION, token)
        }

        let proofs_header = self
            .ucan_proofs
            .drain(..)
            .map(|ucan| ucan.encode())
            .collect::<Result<Vec<String>, _>>()?
            .join(", ");
        if !proofs_header.is_empty() {
            builder = builder.header("ucans", proofs_header);
        }

        if let Some((mime, body)) = self.body.take() {
            Ok(builder
                .header(http::header::CONTENT_TYPE, mime.as_ref())
                .body(body)?)
        } else {
            Ok(builder.body(Body::from(vec![]))?)
        }
    }
}
