//! QUIC version 2 (RFC 9369) and compatible version negotiation (RFC 9368)

use super::util::*;
use super::*;
use crate::QUIC_VERSION_2;
use crate::crypto::Keys;
use crate::crypto::rustls::{
    QuicClientConfig, QuicServerConfig, configured_provider, initial_keys,
    initial_suite_from_provider,
};
use crate::packet::{FixedLengthConnectionIdParser, PartialDecode};

/// Endpoints that support both QUIC versions, version 2 first if `v2_first`
fn pair_supporting_v2(v2_first: bool) -> Pair {
    let versions = match v2_first {
        true => vec![QUIC_VERSION_2, 1],
        false => vec![1, QUIC_VERSION_2],
    };
    let mut endpoint = EndpointConfig::default();
    endpoint.supported_versions(versions);
    let mut pair = Pair::new(Arc::new(endpoint), server_config());
    pair.client.sent_datagrams = Some(Vec::new());
    pair.server.sent_datagrams = Some(Vec::new());
    pair
}

/// Version and raw long header type code of every long header packet in `datagrams`
fn long_headers(datagrams: &[Bytes]) -> Vec<(u32, u8)> {
    let mut headers = Vec::new();
    for datagram in datagrams {
        let mut rest = Some(BytesMut::from(&datagram[..]));
        while let Some(data) = rest.take() {
            let first = data[0];
            let Ok((decode, next)) = PartialDecode::new(
                data,
                &FixedLengthConnectionIdParser::new(8),
                &[1, QUIC_VERSION_2],
                true,
            ) else {
                break;
            };
            if let Some(version) = decode.version() {
                headers.push((version, (first & 0x30) >> 4));
            }
            rest = next;
        }
    }
    headers
}

/// The Retry of RFC 9369, appendix A.4
#[test]
fn retry_integrity_tag() {
    let packet = hex!(
        "cf6b3343cf0008f067a5502a4262b574 6f6b656ec8646ce8bfe33952d9555436
         65dcc7b6"
    );
    let (packet, tag) = packet.split_at(packet.len() - 16);
    let orig_dst_cid = ConnectionId::new(&hex!("8394c8f03e515708"));
    let crypto = server_crypto();
    let computed = crypto::ServerConfig::retry_tag(&crypto, QUIC_VERSION_2, &orig_dst_cid, packet);
    assert_eq!(computed[..], tag[..]);
    // Version 1 uses another key
    let computed = crypto::ServerConfig::retry_tag(&crypto, 1, &orig_dst_cid, packet);
    assert_ne!(computed[..], tag[..]);
}

/// A connection started in version 2, with a Retry and 0-RTT, uses the version 2 packet types
#[test]
fn handshake() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(false);
    pair.server.handle_incoming = Box::new(validate_incoming);
    let mut config = client_config();
    config.version(QUIC_VERSION_2);

    let client_ch = pair.begin_connect(config.clone());
    pair.drive();
    pair.server.assert_accept();
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt(0), [][..].into());
    pair.drive();

    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    let _ = chunks.finalize();

    let client = long_headers(pair.client.sent_datagrams.as_ref().unwrap());
    let server = long_headers(pair.server.sent_datagrams.as_ref().unwrap());
    assert!(
        client
            .iter()
            .chain(&server)
            .all(|&(v, _)| v == QUIC_VERSION_2)
    );
    // Initial 0b01, 0-RTT 0b10, Handshake 0b11
    for ty in [1, 2, 3] {
        assert!(
            client.iter().any(|&(_, t)| t == ty),
            "client sent no type {ty}"
        );
    }
    // Retry 0b00, Initial 0b01, Handshake 0b11
    for ty in [0, 1, 3] {
        assert!(
            server.iter().any(|&(_, t)| t == ty),
            "server sent no type {ty}"
        );
    }
}

/// TLS secrets as logged by rustls, by label
#[derive(Debug, Default)]
struct Secrets(Mutex<std::collections::HashMap<String, Vec<u8>>>);

impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .insert(label.to_owned(), secret.to_vec());
    }
}

/// Client crypto whose sessions can switch from QUIC version 1 to version 2
///
/// rustls fixes the version of a session when the session starts, so these sessions derive the
/// keys of version 2 themselves from the TLS secrets rustls logs, like a crypto provider that
/// supports compatible version negotiation would. rustls only builds keys of 32 bytes from raw
/// bytes, so the sessions use ChaCha20-Poly1305 with HKDF-SHA256.
struct SwitchingClientConfig {
    inner: Arc<QuicClientConfig>,
    secrets: Arc<Secrets>,
    suite: &'static rustls::Tls13CipherSuite,
    initial: rustls::quic::Suite,
    /// Counts `decrypt` calls on the switched-to version's Initial packet key, to check that the
    /// authenticating Initial packet is decrypted only once.
    switch_decrypts: Arc<std::sync::atomic::AtomicUsize>,
}

impl SwitchingClientConfig {
    fn new() -> Self {
        let provider = configured_provider();
        let chacha = provider
            .cipher_suites
            .iter()
            .copied()
            .find(|cs| cs.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .unwrap();
        let tls_provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: vec![chacha],
            ..(*provider).clone()
        });
        let mut roots = RootCertStore::empty();
        roots.add(CERTIFIED_KEY.cert.der().clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            tls_provider.clone(),
        )
        .build()
        .unwrap();
        let secrets = Arc::new(Secrets::default());
        let mut inner = rustls::ClientConfig::builder_with_provider(tls_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        inner.key_log = secrets.clone();
        let initial = initial_suite_from_provider(&provider).unwrap();
        Self {
            inner: Arc::new(QuicClientConfig::with_initial(Arc::new(inner), initial).unwrap()),
            secrets,
            suite: chacha.tls13().unwrap(),
            initial,
            switch_decrypts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl crypto::ClientConfig for SwitchingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        Ok(Box::new(SwitchingSession {
            inner: crypto::ClientConfig::start_session(
                self.inner.clone(),
                version,
                server_name,
                params,
            )?,
            original: version,
            version,
            level: 0,
            next: None,
            config: self,
        }))
    }
}

struct SwitchingSession {
    inner: Box<dyn crypto::Session>,
    config: Arc<SwitchingClientConfig>,
    original: u32,
    version: u32,
    /// Number of key changes returned so far: 1 = Handshake, 2 = 1-RTT
    level: u8,
    /// Client and server secrets of the next 1-RTT key phase
    next: Option<(Vec<u8>, Vec<u8>)>,
}

impl SwitchingSession {
    /// HKDF-Expand-Label (RFC 8446, section 7.1) with an empty context
    fn expand(&self, secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
        let expander = self
            .config
            .suite
            .hkdf_provider
            .expander_for_okm(&rustls::crypto::tls13::OkmBlock::new(secret));
        let mut out = vec![0; len];
        expander
            .expand_slice(
                &[
                    &(len as u16).to_be_bytes(),
                    &[6 + label.len() as u8],
                    b"tls13 ",
                    label,
                    &[0],
                ],
                &mut out,
            )
            .unwrap();
        out
    }

    fn secret(&self, label: &str) -> Vec<u8> {
        self.config.secrets.0.lock().unwrap()[label].clone()
    }

    fn packet_key(&self, secret: &[u8]) -> Box<dyn crypto::PacketKey> {
        let quic = self.config.suite.quic.unwrap();
        let key: [u8; 32] = self.expand(secret, b"quicv2 key", 32).try_into().unwrap();
        let iv: [u8; 12] = self.expand(secret, b"quicv2 iv", 12).try_into().unwrap();
        Box::new(quic.packet_key(key.into(), iv.into()))
    }

    fn header_key(&self, secret: &[u8]) -> Box<dyn crypto::HeaderKey> {
        let quic = self.config.suite.quic.unwrap();
        let key: [u8; 32] = self.expand(secret, b"quicv2 hp", 32).try_into().unwrap();
        Box::new(quic.header_protection_key(key.into()))
    }

    fn update(&self, secret: &[u8]) -> Vec<u8> {
        self.expand(secret, b"quicv2 ku", 32)
    }
}

impl crypto::Session for SwitchingSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        match self.version {
            QUIC_VERSION_2 => {
                let mut keys = initial_keys(
                    rustls::quic::Version::V2,
                    *dst_cid,
                    side,
                    &self.config.initial,
                );
                // These are the keys `switch_version` derives to authenticate and then process
                // the server's version-switch Initial packet; count their use to check that the packet
                // is decrypted only once.
                keys.packet.remote = Box::new(CountingPacketKey {
                    inner: keys.packet.remote,
                    decrypts: self.config.switch_decrypts.clone(),
                });
                keys
            }
            _ => self.inner.initial_keys(dst_cid, side),
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        let keys = self.inner.write_handshake(buf)?;
        self.level += 1;
        if self.version == self.original {
            return Some(keys);
        }
        let (client, server) = match self.level {
            1 => (
                self.secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                self.secret("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
            ),
            _ => (
                self.secret("CLIENT_TRAFFIC_SECRET_0"),
                self.secret("SERVER_TRAFFIC_SECRET_0"),
            ),
        };
        if self.level == 2 {
            self.next = Some((self.update(&client), self.update(&server)));
        }
        Some(crypto::Keys {
            header: crypto::KeyPair {
                local: self.header_key(&client),
                remote: self.header_key(&server),
            },
            packet: crypto::KeyPair {
                local: self.packet_key(&client),
                remote: self.packet_key(&server),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        if self.version == self.original {
            return self.inner.next_1rtt_keys();
        }
        let (client, server) = self.next.take()?;
        let keys = crypto::KeyPair {
            local: self.packet_key(&client),
            remote: self.packet_key(&server),
        };
        self.next = Some((self.update(&client), self.update(&server)));
        Some(keys)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn set_version(&mut self, version: u32) -> Result<(), crypto::UnsupportedVersion> {
        match (self.original, version) {
            (1, QUIC_VERSION_2 | 1) => {
                self.version = version;
                Ok(())
            }
            _ => Err(crypto::UnsupportedVersion),
        }
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// The key derivation of the test sessions reproduces RFC 9369, appendix A.5
#[test]
fn version_2_key_derivation() {
    let config = Arc::new(SwitchingClientConfig::new());
    let session = SwitchingSession {
        inner: crypto::ClientConfig::start_session(
            config.inner.clone(),
            1,
            "localhost",
            &TransportParameters::default(),
        )
        .unwrap(),
        config,
        original: 1,
        version: QUIC_VERSION_2,
        level: 0,
        next: None,
    };
    let secret = hex!("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b");
    assert_eq!(
        session.expand(&secret, b"quicv2 key", 32)[..],
        hex!("3bfcddd72bcf02541d7fa0dd1f5f9eee a817e09a6963a0e6c7df0f9a1bab90f2")
    );
    assert_eq!(
        session.expand(&secret, b"quicv2 iv", 12)[..],
        hex!("a6b5bc6ab7dafce30ffff5dd")
    );
    assert_eq!(
        session.expand(&secret, b"quicv2 hp", 32)[..],
        hex!("d659760d2ba434a226fd37b35c69e2da 8211d10c4f12538787d65645d5d1b8e2")
    );
    assert_eq!(
        session.update(&secret)[..],
        hex!("c69374c49e3d2a9466fa689e49d476db 5d0dfbc87d32ceeaa6343fd0ae4c7d88")
    );
}

/// A client configuration that offers version 2 besides version 1, like Firefox
fn offering_v2(crypto: Arc<dyn crypto::ClientConfig>) -> ClientConfig {
    let mut versions = VersionInformation::new(vec![QUIC_VERSION_2, 1]);
    versions.grease(GreaseVersion::Random);
    let mut layout = TransportParameterLayout::default();
    layout.version_information(Some(versions)).unwrap();
    let mut transport = TransportConfig::default();
    transport.transport_parameter_layout(layout);
    let mut config = ClientConfig::new(crypto);
    config.transport_config(Arc::new(transport));
    config
}

/// Exchange data in both directions, across a key update
fn exchange_data(pair: &mut Pair, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    for (i, msg) in [&b"before key update"[..], b"after key update"]
        .iter()
        .enumerate()
    {
        if i == 1 {
            pair.client_conn_mut(client_ch).force_key_update();
        }
        pair.client_send(client_ch, s).write(msg).unwrap();
        pair.drive();
        if i == 0 {
            assert_eq!(pair.server_streams(server_ch).accept(Dir::Bi), Some(s));
        }
        let mut recv = pair.server_recv(server_ch, s);
        let mut chunks = recv.read(true).unwrap();
        assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if chunk.bytes == *msg);
        let _ = chunks.finalize();
    }
    pair.server_send(server_ch, s).write(b"reply").unwrap();
    pair.drive();
    let mut recv = pair.client_recv(client_ch, s);
    let mut chunks = recv.read(true).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if chunk.bytes == b"reply"[..]);
    let _ = chunks.finalize();
}

/// A server that prefers version 2 switches a client that offers it, and the client follows
#[test]
fn compatible_negotiation() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(true);
    let config = offering_v2(Arc::new(SwitchingClientConfig::new()));
    let (client_ch, server_ch) = pair.connect_with(config);
    exchange_data(&mut pair, client_ch, server_ch);

    // Both chose the version of their first flight, and the server sends version_information
    // without being configured to
    let peer_info = |conn: &mut Connection| {
        let params = conn.crypto_session().transport_parameters();
        params.unwrap().unwrap().version_information.unwrap()
    };
    let info = peer_info(pair.server_conn_mut(server_ch));
    assert_eq!(info.chosen(), 1);
    let info = peer_info(pair.client_conn_mut(client_ch));
    assert_eq!(info.chosen(), QUIC_VERSION_2);
    assert!(info.lists(1) && info.lists(QUIC_VERSION_2));

    let client = long_headers(pair.client.sent_datagrams.as_ref().unwrap());
    let server = long_headers(pair.server.sent_datagrams.as_ref().unwrap());
    // Only the client's first flight uses version 1
    assert_eq!(client[0], (1, 0));
    assert!(client[1..].iter().all(|&(v, _)| v == QUIC_VERSION_2));
    assert!(server.iter().all(|&(v, _)| v == QUIC_VERSION_2));
}

/// Wraps a real `crypto::ServerConfig`, counting calls to `initial_keys`.
struct CountingServerConfig {
    inner: Arc<QuicServerConfig>,
    initial_keys_calls: std::sync::atomic::AtomicUsize,
}

impl crypto::ServerConfig for CountingServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, crypto::UnsupportedVersion> {
        self.initial_keys_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        self.inner.clone().start_session(version, params)
    }
}

/// Regression test: a server switching versions used to derive the original version's Initial
/// keys a second time (`negotiate_version` in `endpoint.rs`), instead of reusing the same ones
/// that already decrypted the client's first flight (`Endpoint::handle_first_packet`). One
/// switching handshake calls `initial_keys` exactly twice: once for the original version (at
/// first-packet arrival) and once for the negotiated one, not three times.
#[test]
fn switching_reuses_the_original_versions_initial_keys() {
    let _guard = subscribe();
    let counting = Arc::new(CountingServerConfig {
        inner: Arc::new(server_crypto()),
        initial_keys_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut endpoint = EndpointConfig::default();
    endpoint.supported_versions(vec![QUIC_VERSION_2, 1]);
    let mut pair = Pair::new(
        Arc::new(endpoint),
        ServerConfig::with_crypto(counting.clone()),
    );
    let config = offering_v2(Arc::new(SwitchingClientConfig::new()));
    let (client_ch, server_ch) = pair.connect_with(config);
    exchange_data(&mut pair, client_ch, server_ch);

    assert_eq!(
        counting
            .initial_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one derivation for the original version, one for the negotiated one; not a third \
         re-derivation of the original version's keys"
    );
}

/// Wraps a real `crypto::PacketKey`, counting calls to `decrypt`.
struct CountingPacketKey {
    inner: Box<dyn crypto::PacketKey>,
    decrypts: Arc<std::sync::atomic::AtomicUsize>,
}

impl crypto::PacketKey for CountingPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        self.inner.encrypt(packet, buf, header_len)
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), crypto::CryptoError> {
        self.decrypts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.decrypt(packet, header, payload)
    }

    fn tag_len(&self) -> usize {
        self.inner.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.inner.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.inner.integrity_limit()
    }
}

/// A client following a server's version switch decrypts the authenticating Initial packet
/// once: `authenticates_initial` decrypts a clone to check that it authenticates, and
/// `handle_packet` reuses that payload instead of decrypting the original again.
#[test]
fn switch_does_not_decrypt_the_authenticating_packet_twice() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(true);
    let switching = Arc::new(SwitchingClientConfig::new());
    let decrypts = switching.switch_decrypts.clone();
    let config = offering_v2(switching);
    let (client_ch, server_ch) = pair.connect_with(config);
    exchange_data(&mut pair, client_ch, server_ch);

    assert_eq!(
        decrypts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the version-switch Initial must be decrypted once, by authenticates_initial, not again \
         by handle_packet/decrypt_packet"
    );
}

/// A server that prefers version 1 keeps it
#[test]
fn original_version_preferred() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(false);
    let config = offering_v2(Arc::new(SwitchingClientConfig::new()));
    let (client_ch, server_ch) = pair.connect_with(config);
    exchange_data(&mut pair, client_ch, server_ch);

    let client = long_headers(pair.client.sent_datagrams.as_ref().unwrap());
    let server = long_headers(pair.server.sent_datagrams.as_ref().unwrap());
    assert!(client.iter().chain(&server).all(|&(v, _)| v == 1));
}

/// A client whose crypto session cannot switch fails at once instead of waiting for a timeout
#[test]
fn switch_unsupported_by_session() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(true);
    let client_ch = pair.begin_connect(offering_v2(Arc::new(client_crypto())));
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TransportError(TransportError {
                code: TransportErrorCode::VERSION_NEGOTIATION_ERROR,
                ..
            })
        })
    );
}

/// After switching, the server still accepts Initial packets of the original version
#[test]
fn server_accepts_original_version() {
    let _guard = subscribe();
    let mut pair = pair_supporting_v2(true);
    let config = offering_v2(Arc::new(SwitchingClientConfig::new()));
    let client_ch = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    let server_ch = pair.server.assert_accept();
    let crypto_frames = pair.server_conn_mut(server_ch).stats().frame_rx.crypto;

    // The server's first flight is lost, so the client retransmits its first flight
    while pair.server.inbound.is_empty() {
        pair.client.inbound.clear();
        pair.time = pair.client.next_wakeup().unwrap();
        pair.drive_client();
    }
    let (_, _, datagram) = pair.server.inbound.front().unwrap();
    assert_eq!(datagram[1..5], 1u32.to_be_bytes());
    pair.drive_server();
    assert!(pair.server_conn_mut(server_ch).stats().frame_rx.crypto > crypto_frames);

    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::Connected)
    );
}

/// The client offers only versions its endpoint accepts, and its own among them
#[test]
fn offered_versions_are_validated() {
    let server = "[::1]:4433".parse().unwrap();
    let crypto: Arc<dyn crypto::ClientConfig> = Arc::new(client_crypto());
    let mut endpoint = Endpoint::new(Arc::default(), None, true, None);
    assert_matches!(
        endpoint.connect(
            Instant::now(),
            offering_v2(crypto.clone()),
            server,
            "localhost"
        ),
        Err(ConnectError::UnsupportedVersion)
    );

    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(vec![1, QUIC_VERSION_2]);
    let mut endpoint = Endpoint::new(Arc::new(endpoint_config), None, true, None);
    assert!(
        endpoint
            .connect(
                Instant::now(),
                offering_v2(crypto.clone()),
                server,
                "localhost"
            )
            .is_ok()
    );
    let mut config = offering_v2(crypto);
    config.version(QUIC_VERSION_2);
    let mut layout = TransportParameterLayout::default();
    layout
        .version_information(Some(VersionInformation::new(vec![1])))
        .unwrap();
    let mut transport = TransportConfig::default();
    transport.transport_parameter_layout(layout);
    config.transport_config(Arc::new(transport));
    assert_matches!(
        endpoint.connect(Instant::now(), config, server, "localhost"),
        Err(ConnectError::UnsupportedVersion)
    );
}
