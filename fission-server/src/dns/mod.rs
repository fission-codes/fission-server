//! DNS

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::broadcast;
use trust_dns_server::server::{Request, RequestHandler};

use self::{request_handler::Handler, response_handler::Handle};
use crate::db::Pool;

pub mod request_handler;
pub mod response;
pub mod response_handler;

pub use self::response::Response;

/// Handle a DNS request
pub async fn handle_request(request: Request, db_pool: Pool) -> Result<Bytes> {
    let (tx, mut rx) = broadcast::channel(1);
    let response_handle = Handle(tx);

    Handler::new(db_pool)
        .handle_request(&request, response_handle)
        .await;

    rx.recv().await.map_err(|err| err.into())
}
