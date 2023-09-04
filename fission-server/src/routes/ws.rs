//! Websocket relay

use std::net::SocketAddr;

use axum::{
    extract::{ws::WebSocket, ConnectInfo, Path, State, WebSocketUpgrade},
    response::Response,
};
use futures::{channel::mpsc, future, pin_mut, StreamExt, TryStreamExt};

use crate::{
    app_state::{AppState, WsPeerMap},
    traits::ServerSetup,
};

/// Websocket handler
pub async fn handler<S: ServerSetup>(
    ws: WebSocketUpgrade,
    Path(did): Path<String>,
    State(state): State<AppState<S>>,
    ConnectInfo(src_addr): ConnectInfo<SocketAddr>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(did, socket, state.ws_peer_map, src_addr))
}

async fn handle_socket(did: String, socket: WebSocket, peers: WsPeerMap, src_addr: SocketAddr) {
    let (tx, rx) = mpsc::channel(64);
    let (outgoing, incoming) = socket.split();

    peers.entry(did.clone()).or_default().insert(src_addr, tx);

    let broadcast = incoming.try_for_each({
        let did = did.clone();
        let peers = peers.clone();
        move |msg| {
            let did_peers = peers.get(&did).expect("did should be present in peers");
            let recipients = did_peers
                .iter()
                .filter(|pair| pair.key() != &src_addr)
                .map(|pair| pair.value().clone());

            for mut recipient in recipients {
                // If the recipient is no longer available, continue to the next
                if recipient.try_send(msg.clone()).is_err() {
                    continue;
                };
            }

            future::ok(())
        }
    });

    let receive = rx.map(Ok).forward(outgoing);

    pin_mut!(broadcast, receive);
    future::select(broadcast, receive).await;

    peers
        .get(&did)
        .expect("did should be present in peers")
        .remove(&src_addr);
}
