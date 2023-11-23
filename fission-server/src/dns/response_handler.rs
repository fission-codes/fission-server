//! DNS Response Handler

use async_trait::async_trait;
use bytes::Bytes;
use hickory_server::{
    authority::MessageResponse,
    proto::{self, serialize::binary::BinEncoder},
    server::{ResponseHandler, ResponseInfo},
};
use std::io;
use tokio::sync::broadcast;

/// A handle to the channel over which the response to a DNS request will be sent
#[derive(Debug, Clone)]
pub struct Handle(pub broadcast::Sender<Bytes>);

#[async_trait]
impl ResponseHandler for Handle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };

        let bytes = Bytes::from(bytes);
        self.0.send(bytes).unwrap();

        Ok(info)
    }
}
