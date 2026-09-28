//! Crypto sessions that finish part of the handshake asynchronously

use std::{
    any::Any,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};

use assert_matches::assert_matches;

use super::util::*;
use super::*;
use crate::{
    ConnectError, Side, TransportErrorCode,
    connection::SentPacketLog,
    crypto::{self, ExportKeyingMaterialError, KeyPair, Keys, PacketKey, Session},
    packet::SpaceId,
    shared::ConnectionId,
    transport_parameters::TransportParameters,
};

/// Lets a test decide when a [`GatedSession`] finishes its asynchronous work
#[derive(Default)]
pub(super) struct Gate(Mutex<GateState>);

#[derive(Default)]
struct GateState {
    open: bool,
    error: Option<TransportError>,
    waker: Option<Waker>,
    woken: bool,
}

impl Gate {
    /// Finish the work, successfully or with `error`, and wake the connection
    pub(super) fn open(&self, error: Option<TransportError>) {
        let mut state = self.0.lock().unwrap();
        state.open = true;
        state.error = error;
        if let Some(waker) = state.waker.take() {
            state.woken = true;
            waker.wake();
        }
    }

    /// Whether a session waits for the gate
    pub(super) fn is_waiting(&self) -> bool {
        let state = self.0.lock().unwrap();
        state.waker.is_some() && !state.open
    }

    /// Whether opening the gate woke a connection
    pub(super) fn woke(&self) -> bool {
        self.0.lock().unwrap().woken
    }
}

/// A client configuration whose sessions hold back the handshake data that follows the
/// ServerHello until the [`Gate`] opens, like a session that verifies the server's certificate
/// on another thread
pub(super) struct GatedClientConfig {
    pub(super) inner: Arc<dyn crypto::ClientConfig>,
    pub(super) gate: Arc<Gate>,
}

impl crypto::ClientConfig for GatedClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        Ok(Box::new(GatedSession {
            inner: self
                .inner
                .clone()
                .start_session(version, server_name, params)?,
            gate: self.gate.clone(),
            handshake_keys: false,
            held: Vec::new(),
        }))
    }
}

struct GatedSession {
    inner: Box<dyn Session>,
    gate: Arc<Gate>,
    /// Whether the Handshake keys have been handed out, after which data is held back
    handshake_keys: bool,
    /// Handshake data received while the gate is closed
    held: Vec<Vec<u8>>,
}

impl Session for GatedSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if !self.handshake_keys {
            return self.inner.read_handshake(buf);
        }
        // Everything after the ServerHello waits for the gate, in order
        self.held.push(buf.to_vec());
        Ok(false)
    }

    fn poll_handshake(&mut self, waker: &Waker) -> Poll<Result<(), TransportError>> {
        if self.held.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.gate.0.lock().unwrap();
        if !state.open {
            state.waker = Some(waker.clone());
            return Poll::Pending;
        }
        if let Some(error) = state.error.take() {
            return Poll::Ready(Err(error));
        }
        drop(state);
        for data in self.held.drain(..) {
            self.inner.read_handshake(&data)?;
        }
        Poll::Ready(Ok(()))
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = self.inner.write_handshake(buf);
        self.handshake_keys |= keys.is_some();
        keys
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// Start connecting with a gated session and deliver the server's first flight, after which the
/// client waits for the gate
///
/// Returns the client's connection handle and the time the flight arrived.
pub(super) fn connect_until_waiting(
    pair: &mut Pair,
    config: ClientConfig,
    gate: &Gate,
) -> (ConnectionHandle, Instant) {
    pair.client.log_sent_packets = true;
    pair.server.log_sent_packets = true;
    let client_ch = pair.begin_connect(config);
    pair.drive_client();
    pair.time += pair.latency;
    pair.drive_server();
    pair.time += pair.latency;
    pair.drive_client();
    assert!(gate.is_waiting());
    (client_ch, pair.time)
}

fn gated_config(gate: &Arc<Gate>) -> ClientConfig {
    ClientConfig::new(Arc::new(GatedClientConfig {
        inner: Arc::new(client_crypto()),
        gate: gate.clone(),
    }))
}

/// The client's packets that carry CRYPTO frames in the Handshake space
fn finished_packets(log: &[SentPacketLog]) -> Vec<&SentPacketLog> {
    log.iter()
        .filter(|p| {
            p.space == SpaceId::Handshake
                && frame::Iter::new(p.payload.clone())
                    .unwrap()
                    .any(|f| matches!(f, Ok(frame::Frame::Crypto(_))))
        })
        .collect()
}

/// When the session finishes its work, the Finished goes out at once, not after a probe timeout,
/// and the server's 1-RTT packets that arrived in the meantime are not lost
#[test]
fn finished_sent_when_woken() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.latency = Duration::from_millis(10);
    let gate = Arc::new(Gate::default());
    let (client_ch, arrival) = connect_until_waiting(&mut pair, gated_config(&gate), &gate);
    assert!(finished_packets(pair.client_conn_mut(client_ch).sent_log()).is_empty());

    // Verification takes 5 ms, less than a probe timeout
    pair.time += Duration::from_millis(5);
    gate.open(None);
    assert!(gate.woke());
    pair.drive_client();
    let finished = finished_packets(pair.client_conn_mut(client_ch).sent_log())
        .into_iter()
        .map(|p| p.time)
        .collect::<Vec<_>>();
    assert_eq!(finished, [arrival + Duration::from_millis(5)]);

    pair.drive();
    let server_ch = pair.server.assert_accept();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    assert!(!pair.client_conn_mut(client_ch).is_closed());
    // No probe was needed before the Finished
    let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
    assert!(
        log.iter()
            .take_while(|p| finished_packets(std::slice::from_ref(p)).is_empty())
            .all(|p| frame::Iter::new(p.payload.clone())
                .unwrap()
                .all(|f| !matches!(f, Ok(frame::Frame::Ping)))),
        "{log:#?}"
    );
    let client = pair.client_conn_mut(client_ch).stats();
    // The server's 1-RTT packet of its first flight was kept and processed
    assert_eq!(pair.server_conn_mut(server_ch).stats().path.lost_packets, 0);
    assert!(client.frame_rx.new_connection_id > 0);

    // The connection works
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, s).write(b"hello").unwrap();
    pair.drive();
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Uni), Some(id) if id == s);
}

/// An error of the asynchronous work closes the connection like any handshake error
#[test]
fn async_handshake_error() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.latency = Duration::from_millis(10);
    let gate = Arc::new(Gate::default());
    let (client_ch, _) = connect_until_waiting(&mut pair, gated_config(&gate), &gate);

    let error = TransportError {
        code: TransportErrorCode::crypto(42),
        frame: None,
        reason: "bad certificate".into(),
    };
    pair.time += Duration::from_millis(5);
    gate.open(Some(error));
    pair.drive_client();
    assert!(pair.client_conn_mut(client_ch).is_closed());
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(TransportError { code, .. })
        }) if code == TransportErrorCode::crypto(42)
    );
    // The server learns why
    pair.drive();
    let server_ch = pair.server.assert_accept();
    let conn = pair.server_conn_mut(server_ch);
    let reason = std::iter::from_fn(|| conn.poll()).find_map(|event| match event {
        Event::ConnectionLost { reason } => Some(reason),
        _ => None,
    });
    assert_matches!(
        reason,
        Some(ConnectionError::ConnectionClosed(frame::ConnectionClose { error_code, .. }))
            if error_code == TransportErrorCode::crypto(42)
    );
}

/// The session finishes its work before the connection polls it, and the next packet to arrive
/// is an Initial: the handshake completes with that packet instead of hanging until the idle
/// timeout
#[test]
fn async_work_finished_before_initial_retransmission() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.latency = Duration::from_millis(10);
    let gate = Arc::new(Gate::default());
    // quiche's acknowledgement delay keeps the client's Initial keys until the timer fires
    let mut fingerprint = crate::FingerprintConfig::default();
    fingerprint.ack_policy(crate::AckPolicy::Quiche);
    let mut transport = TransportConfig::default();
    transport.fingerprint(fingerprint);
    let mut config = gated_config(&gate);
    config.transport_config(Arc::new(transport));
    let (client_ch, _) = connect_until_waiting(&mut pair, config, &gate);
    assert!(
        !pair
            .client_conn_mut(client_ch)
            .sent_log()
            .iter()
            .any(|p| p.space == SpaceId::Handshake),
        "the client still has its Initial keys"
    );

    // Verification is done, but the connection has not polled the session yet
    gate.open(None);
    // The server retransmits its Initial after a probe timeout
    pair.time = pair.server.next_wakeup().unwrap();
    pair.drive_server();
    let initials = pair
        .client
        .inbound
        .drain(..)
        .filter_map(|(time, ecn, mut datagram)| {
            // Only the Initial packet of each datagram
            let (partial, _) = crate::packet::PartialDecode::new(
                datagram.clone(),
                &crate::packet::FixedLengthConnectionIdParser::new(0),
                &[1],
                true,
            )
            .unwrap();
            if !partial.is_initial() {
                return None;
            }
            datagram.truncate(partial.len());
            Some((time, ecn, datagram))
        })
        .collect::<Vec<_>>();
    assert!(!initials.is_empty());
    pair.client.inbound.extend(initials);
    pair.time += pair.latency;
    // The client handles the Initial before it polls the session
    pair.drive_client();
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    pair.drive();
    pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// A waker that records its own id when woken, to tell apart the waker
/// `poll_handshake` currently holds from a stale one a session kept around.
/// `test_waker()` (used by [`Pair::drive`]) is a fresh no-op `Waker` on every
/// call, so it cannot tell the two apart; this one can.
struct SpyWaker {
    id: usize,
    woken: Arc<Mutex<Option<usize>>>,
}

impl std::task::Wake for SpyWaker {
    fn wake(self: Arc<Self>) {
        *self.woken.lock().unwrap() = Some(self.id);
    }
}

fn spy_waker(id: usize, woken: Arc<Mutex<Option<usize>>>) -> Waker {
    Waker::from(Arc::new(SpyWaker { id, woken }))
}

/// [`Connection::poll_handshake`] replaces the waker a previous call registered with the
/// session: only the most recently passed waker is ever woken, never an earlier one, even
/// though [`crypto::Session::poll_handshake`] itself only clones whatever it is currently
/// given.
#[test]
fn poll_handshake_wakes_only_the_latest_waker() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let gate = Arc::new(Gate::default());
    let (client_ch, now) = connect_until_waiting(&mut pair, gated_config(&gate), &gate);

    let woken = Arc::new(Mutex::new(None));
    // Two more polls with distinct wakers while the session is still pending, as repeated
    // polls of a real connection driver would do.
    pair.client_conn_mut(client_ch)
        .poll_handshake(now, &spy_waker(1, woken.clone()));
    pair.client_conn_mut(client_ch)
        .poll_handshake(now, &spy_waker(2, woken.clone()));

    gate.open(None);
    assert_eq!(
        *woken.lock().unwrap(),
        Some(2),
        "only the most recently registered waker may be woken"
    );
}
