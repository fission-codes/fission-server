//! DNS Request Handler

use trust_dns_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {}

impl Handler {
    /// Create new handler from command-line options.
    pub fn new() -> Self {
        Handler {}
    }
}

impl Default for Handler {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a DNS request
#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::ServFail);
        let response = builder.build_no_records(header);
        let it = response_handle.send_response(response).await;
        if let Ok(it) = it {
            it
        } else {
            header.into()
        }
    }
}
