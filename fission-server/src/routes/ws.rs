//! Websocket relay

use crate::{app_state::AppState, setups::ServerSetup};
use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    response::Response,
};
use dashmap::{DashMap, DashSet};
use futures::{
    channel::mpsc::{self, Sender},
    future, pin_mut, StreamExt, TryStreamExt,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Info stored per-peer.
#[derive(Debug)]
pub struct WsPeer {
    /// A channel for transmitting messages to a websocket peer
    channel: Sender<Message>,
}

/// A map of all websocket peers connected to each DID-specific channel
#[derive(Debug, Default)]
pub struct WsPeerMap {
    /// The next identifier for a peer. Used for associating peers to addresses
    pub next_id: AtomicUsize,
    /// A map of all peers connected
    pub peers: DashMap<usize, WsPeer>,
    /// A map of all active topics and which peers are connected to them
    pub topics: DashMap<String, DashSet<usize>>,
}

impl WsPeerMap {
    fn add_peer(&self, peer: WsPeer) -> usize {
        let peer_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.peers.insert(peer_id, peer);

        peer_id
    }

    fn topic_subscribe(&self, peer_id: usize, topic: &str) {
        self.topics
            .entry(topic.to_string())
            .or_default()
            .insert(peer_id);
    }

    fn topic_unsubscribe(&self, peer_id: usize, topic: &str) {
        if let Some(peer_set) = self.topics.get(topic) {
            peer_set.remove(&peer_id);
        }
        self.topics
            .remove_if(topic, |_, peer_set| peer_set.is_empty());
    }

    fn remove_peer(&self, peer_id: usize) {
        self.peers.remove(&peer_id);
    }

    /// Broadcast `message` on `topic`.
    /// You can filter out one peer from the recipients via `filter_peer_id`,
    /// e.g. to filter out the peer that triggered the message in said topic.
    pub fn broadcast_on_topic(&self, topic: &str, message: Message, filter_peer_id: Option<usize>) {
        let Some(topic_peers) = self
            .topics
            .get(topic) else {
            tracing::warn!(topic, "Topic got closed while trying to send.");
            return;
        };

        let recipients = topic_peers.iter().filter_map(|entry| {
            if Some(*entry.key()) != filter_peer_id {
                self.peers.get_mut(entry.key())
            } else {
                None
            }
        });

        for mut recipient in recipients {
            // If the recipient is no longer available, continue to the next
            tracing::trace!(
                topic,
                text = message.to_text().ok(),
                "Outgoing websocket msg"
            );
            if let Err(e) = recipient.channel.try_send(message.clone()) {
                tracing::warn!(?e, "Recipient unavailable");
            }
        }
    }

    /// Send a message to only a single peer by peer_id
    pub fn send_message(&self, recipient_id: usize, message: Message) -> Result<()> {
        if let Some(mut peer) = self.peers.get_mut(&recipient_id) {
            peer.channel.try_send(message)?
        }

        Ok(())
    }
}

/// Websocket handler
pub async fn handler<S: ServerSetup>(
    ws: WebSocketUpgrade,
    Path(topic): Path<String>,
    State(state): State<AppState<S>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(topic, socket, state.ws_peer_map))
}

async fn handle_socket(topic: String, socket: WebSocket, map: Arc<WsPeerMap>) {
    let (tx, rx) = mpsc::channel(64);
    let (outgoing, incoming) = socket.split();

    tracing::debug!(topic, "websocket peer connected");

    let peer_id = map.add_peer(WsPeer { channel: tx });
    map.topic_subscribe(peer_id, &topic);

    let broadcast = incoming.try_for_each(|msg| async {
        match msg {
            Message::Ping(data) => {
                if let Err(e) = map.send_message(peer_id, Message::Pong(data)) {
                    tracing::warn!(?e, "Couldn't send websocket pong");
                }
            }
            Message::Binary(_) | Message::Text(_) => {
                tracing::trace!(topic, text = msg.to_text().ok(), "Incoming websocket msg");
                map.broadcast_on_topic(&topic, msg, Some(peer_id));
            }
            Message::Pong(_) | Message::Close(_) => {}
        };
        Ok(())
    });

    let receive = rx.map(Ok).forward(outgoing);

    pin_mut!(broadcast, receive);
    future::select(broadcast, receive).await;

    tracing::debug!(topic, "websocket peer disconnected");

    // Cleanup once the peer disconnects:
    map.topic_unsubscribe(peer_id, &topic);
    map.remove_peer(peer_id);
}
