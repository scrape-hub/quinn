//! Browser-like wire behaviour, checked on the datagrams a client actually sends
//!
//! The expected values come from captures of Chrome 153 and Firefox 156 connecting to
//! www.google.com. The ClientHello produced by rustls is inflated with ALPN protocols so that it
//! needs two Initial packets, like a browser's post-quantum ClientHello.

use std::{ops::RangeInclusive, sync::Arc};

use bytes::{Bytes, BytesMut};

use super::util::*;
use super::*;
use crate::test_profiles::{
    chrome_endpoint, chrome_transport, firefox_endpoint, firefox_transport,
};
use crate::{
    AckDecimation, AckPolicy, BufferedPacketProcessing, FingerprintConfig, FirstPacketNumber,
    InitialPadding, PacketNumbering, PacketPadding,
    connection::SentPacketLog,
    crypto::{Keys, ServerConfig as _},
    packet::{FixedLengthConnectionIdParser, PartialDecode, SpaceId},
};

/// ALPN protocols that inflate the ClientHello beyond one Initial packet
fn alpn() -> Vec<Vec<u8>> {
    (0..24)
        .map(|i| format!("proto-{i:02}-{}", "x".repeat(40)).into_bytes())
        .collect()
}

fn pair(client: EndpointConfig) -> Pair {
    pair_with_server(
        client,
        server_crypto_with_alpn(vec![alpn()[7].clone()]),
        false,
    )
}

/// A pair whose server uses `crypto`, and numbers its packets like Google's quiche server if
/// `google_numbering` is set: one counter for all packet number spaces, so that its first 1-RTT
/// packet follows a gap
fn pair_with_server(
    client: EndpointConfig,
    crypto: crate::crypto::rustls::QuicServerConfig,
    google_numbering: bool,
) -> Pair {
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    // Keep the server from updating keys, so that any key update would be the client's
    let mut fingerprint = FingerprintConfig::default();
    fingerprint.early_key_update(false);
    if google_numbering {
        fingerprint.packet_numbering(PacketNumbering::Shared { first: 1 });
    }
    let mut transport = TransportConfig::default();
    transport.fingerprint(fingerprint);
    server_config.transport_config(Arc::new(transport));
    let server = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server_config)),
        true,
        None,
    );
    let client = Endpoint::new(Arc::new(client), None, true, None);
    let mut pair = Pair::new_from_endpoint(client, server);
    pair.client.sent_datagrams = Some(Vec::new());
    pair.client.log_sent_packets = true;
    pair.server.log_sent_packets = true;
    pair
}

fn browser_config(transport: TransportConfig) -> ClientConfig {
    let mut config = ClientConfig::new(Arc::new(client_crypto_with_alpn(alpn())));
    config
        .transport_config(Arc::new(transport))
        .initial_dst_cid_provider(Arc::new(|| {
            RandomConnectionIdGenerator::new(8).generate_cid()
        }));
    config
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    Crypto(u64, Bytes),
    Ping,
    Padding(usize),
    Ack,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Packet {
    Initial {
        pn: u64,
        pn_len: usize,
        frames: Vec<Frame>,
    },
    /// A packet that cannot be decrypted with the Initial keys
    Other { first_byte: u8, len: usize },
    /// Zero bytes after the last packet
    Zeros(usize),
}

impl Packet {
    /// Whether this is a 0-RTT packet, whatever the value of the fixed bit
    fn is_0rtt(&self) -> bool {
        matches!(self, Self::Other { first_byte, .. } if first_byte & 0xb0 == 0x90)
    }

    fn crypto(&self) -> Vec<(u64, Bytes)> {
        match self {
            Self::Initial { frames, .. } => frames
                .iter()
                .filter_map(|f| match f {
                    Frame::Crypto(offset, data) => Some((*offset, data.clone())),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn pings(&self) -> usize {
        match self {
            Self::Initial { frames, .. } => frames.iter().filter(|f| **f == Frame::Ping).count(),
            _ => 0,
        }
    }
}

/// Split a datagram into packets, decrypting Initial packets with `keys`
///
/// `largest` is the largest Initial packet number decoded so far.
fn decode(datagram: &Bytes, keys: &Keys, largest: &mut u64) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut rest = Some(BytesMut::from(&datagram[..]));
    while let Some(data) = rest.take() {
        if data.iter().all(|b| *b == 0) {
            packets.push(Packet::Zeros(data.len()));
            break;
        }
        let first_byte = data[0];
        let (partial, remaining) =
            PartialDecode::new(data, &FixedLengthConnectionIdParser::new(8), &[1], true).unwrap();
        rest = remaining;
        if !partial.is_initial() {
            packets.push(Packet::Other {
                first_byte,
                len: partial.len(),
            });
            continue;
        }
        let mut packet = partial.finish(Some(&*keys.header.remote)).unwrap();
        let number = packet.header.number().unwrap();
        let pn = number.expand(*largest + 1);
        *largest = (*largest).max(pn);
        keys.packet
            .remote
            .decrypt(pn, &packet.header_data, &mut packet.payload)
            .unwrap();
        let mut frames: Vec<Frame> = Vec::new();
        for frame in frame::Iter::new(packet.payload.freeze()).unwrap() {
            match frame.unwrap() {
                frame::Frame::Crypto(c) => frames.push(Frame::Crypto(c.offset, c.data)),
                frame::Frame::Ping => frames.push(Frame::Ping),
                frame::Frame::Padding => match frames.last_mut() {
                    Some(Frame::Padding(n)) => *n += 1,
                    _ => frames.push(Frame::Padding(1)),
                },
                frame::Frame::Ack(_) => frames.push(Frame::Ack),
                _ => frames.push(Frame::Other),
            }
        }
        packets.push(Packet::Initial {
            pn,
            pn_len: number.len(),
            frames,
        });
    }
    packets
}

/// Decode all datagrams of a connection attempt, using the Initial keys derived from the
/// destination connection ID of the first one
fn decode_all(datagrams: &[Bytes]) -> Vec<(usize, Vec<Packet>)> {
    let (first, _) = PartialDecode::new(
        BytesMut::from(&datagrams[0][..]),
        &FixedLengthConnectionIdParser::new(8),
        &[1],
        true,
    )
    .unwrap();
    let keys = server_crypto().initial_keys(1, first.dst_cid()).unwrap();
    let mut largest = 0;
    datagrams
        .iter()
        .map(|d| (d.len(), decode(d, &keys, &mut largest)))
        .collect()
}

/// Reassemble the ClientHello from the CRYPTO frames of the given packets
fn client_hello<'a>(packets: impl Iterator<Item = &'a Packet>) -> Vec<u8> {
    let mut hello = Vec::new();
    for (offset, data) in packets.flat_map(|p| p.crypto()) {
        let end = offset as usize + data.len();
        if hello.len() < end {
            hello.resize(end, 0);
        }
        hello[offset as usize..end].copy_from_slice(&data);
    }
    hello
}

/// Sorted, merged CRYPTO ranges of a packet
fn coverage(packet: &Packet) -> Vec<(u64, u64)> {
    let mut ranges = packet
        .crypto()
        .iter()
        .map(|(o, d)| (*o, *o + d.len() as u64))
        .collect::<Vec<_>>();
    ranges.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// A frame of a packet the client sent
#[derive(Debug, Clone, PartialEq, Eq)]
enum F {
    Padding(usize),
    Ping,
    /// The acknowledged ranges, largest first
    Ack(Vec<RangeInclusive<u64>>),
    Crypto,
    Stream(StreamId),
    /// A NEW_CONNECTION_ID frame with its sequence number
    NewConnectionId(u64),
    /// A MAX_DATA frame with its limit
    MaxData(u64),
    Other,
}

/// A packet the client sent, decoded from its plaintext
#[derive(Debug, Clone)]
struct Sent {
    time: Instant,
    space: SpaceId,
    zero_rtt: bool,
    len: usize,
    frames: Vec<F>,
}

impl Sent {
    fn new(log: SentPacketLog) -> Self {
        let mut frames: Vec<F> = Vec::new();
        for frame in frame::Iter::new(log.payload).unwrap() {
            match frame.unwrap() {
                frame::Frame::Padding => match frames.last_mut() {
                    Some(F::Padding(n)) => *n += 1,
                    _ => frames.push(F::Padding(1)),
                },
                frame::Frame::Ping => frames.push(F::Ping),
                frame::Frame::Ack(ack) => frames.push(F::Ack(ack.iter().collect())),
                frame::Frame::Crypto(_) => frames.push(F::Crypto),
                frame::Frame::Stream(stream) => frames.push(F::Stream(stream.id)),
                frame::Frame::NewConnectionId(frame) => {
                    frames.push(F::NewConnectionId(frame.sequence))
                }
                frame::Frame::MaxData(limit) => frames.push(F::MaxData(limit.into_inner())),
                _ => frames.push(F::Other),
            }
        }
        Self {
            time: log.time,
            space: log.space,
            zero_rtt: log.zero_rtt,
            len: log.len,
            frames,
        }
    }

    fn is_1rtt(&self) -> bool {
        self.space == SpaceId::Data && !self.zero_rtt
    }

    fn ack(&self) -> Option<&[RangeInclusive<u64>]> {
        self.frames.iter().find_map(|f| match f {
            F::Ack(ranges) => Some(&ranges[..]),
            _ => None,
        })
    }

    /// Whether the packet carries nothing but an ACK frame and padding
    fn is_ack_only(&self) -> bool {
        self.ack().is_some()
            && self
                .frames
                .iter()
                .all(|f| matches!(f, F::Ack(_) | F::Padding(_)))
    }

    fn has(&self, frame: &F) -> bool {
        self.frames.contains(frame)
    }

    fn has_stream_frame(&self) -> bool {
        self.frames.iter().any(|f| matches!(f, F::Stream(_)))
    }
}

/// The datagrams the client of `pair` sent on connection `ch`: their lengths and the packets in
/// them, decoded from what the connection logged before encryption
fn sent_datagrams(pair: &mut Pair, ch: ConnectionHandle) -> Vec<(usize, Vec<Sent>)> {
    let raw = pair.client.sent_datagrams.clone().unwrap();
    let mut log = pair.client_conn_mut(ch).sent_log().to_vec().into_iter();
    let datagrams = raw
        .iter()
        .map(|datagram| {
            let mut packets = Vec::new();
            let mut rest = Some(BytesMut::from(&datagram[..]));
            while let Some(data) = rest.take() {
                if data.iter().all(|b| *b == 0) {
                    break;
                }
                let (partial, remaining) = PartialDecode::new(
                    data.clone(),
                    &FixedLengthConnectionIdParser::new(8),
                    &[1],
                    true,
                )
                .unwrap();
                rest = remaining;
                let entry = log.next().expect("every packet is logged");
                // neqo pads a datagram carrying an Initial packet with zeros even after a 1-RTT
                // packet, which then extend that packet
                let zeros_after = entry.space == SpaceId::Data
                    && !entry.zero_rtt
                    && data[entry.len..].iter().all(|b| *b == 0);
                assert!(entry.len == partial.len() || zeros_after, "{entry:?}");
                packets.push(Sent::new(entry));
            }
            (datagram.len(), packets)
        })
        .collect();
    assert!(log.next().is_none(), "logged packets without datagram");
    datagrams
}

/// All packets the client of `pair` sent on connection `ch`
fn sent_packets(pair: &mut Pair, ch: ConnectionHandle) -> Vec<Sent> {
    sent_datagrams(pair, ch)
        .into_iter()
        .flat_map(|(_, packets)| packets)
        .collect()
}

/// When the server of `pair` sent its first 1-RTT packet on connection `ch`
fn server_first_1rtt(pair: &mut Pair, ch: ConnectionHandle) -> Instant {
    pair.server_conn_mut(ch)
        .sent_log()
        .iter()
        .find(|p| p.space == SpaceId::Data && !p.zero_rtt)
        .expect("server sent 1-RTT packets")
        .time
}

/// Open a bidirectional stream, send a request, answer it and read the answer
fn exchange(pair: &mut Pair, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(b"request").unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Bi), Some(id) if id == s);
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if &chunk.bytes[..] == b"request");
    let _ = chunks.finalize();
    let response = vec![0x42; 100_000];
    let mut written = 0;
    while written < response.len() {
        written += pair
            .server_send(server_ch, s)
            .write(&response[written..])
            .unwrap_or(0);
        pair.drive();
        let mut recv = pair.client_recv(client_ch, s);
        let mut chunks = recv.read(false).unwrap();
        while let Ok(Some(_)) = chunks.next(usize::MAX) {}
        let _ = chunks.finalize();
    }
}

#[test]
fn chrome_like_client() {
    let _guard = subscribe();
    let mut pair = pair(chrome_endpoint());
    // Without latency, a probe timeout would fire while the Finished waits for the application
    pair.latency = Duration::from_millis(10);
    let (client_ch, server_ch) = pair.connect_with(browser_config(chrome_transport()));
    exchange(&mut pair, client_ch, server_ch);
    assert!(!pair.client_conn_mut(client_ch).is_closed());

    let datagrams = decode_all(pair.client.sent_datagrams.as_ref().unwrap());
    let initials = datagrams
        .iter()
        .filter(|(_, p)| matches!(p[0], Packet::Initial { .. }))
        .collect::<Vec<_>>();
    for (len, packets) in &datagrams {
        // quiche only coalesces its reply to the server's flight, and no datagram exceeds the
        // Initial size
        if !packets
            .iter()
            .any(|p| matches!(p, Packet::Other { first_byte, .. } if first_byte & 0xf0 == 0xe0))
        {
            assert_eq!(packets.len(), 1, "{packets:?}");
        }
        assert!(*len <= 1250);
        if let Packet::Other { first_byte, .. } = packets[0] {
            if first_byte & 0x80 == 0 {
                assert_eq!(first_byte & 0x20, 0, "spin bit set");
                assert_ne!(first_byte & 0x40, 0, "fixed bit cleared");
            }
        }
    }
    for (len, _) in &initials {
        assert_eq!(*len, 1250);
    }

    // Packet numbers 1, 2, ... with a two-byte number on the second packet
    let numbers = initials
        .iter()
        .map(|(_, p)| match &p[0] {
            Packet::Initial { pn, pn_len, .. } => (*pn, *pn_len),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();
    assert_eq!(numbers[..2], [(1, 1), (2, 2)]);
    assert!(numbers[2..].iter().all(|&(_, len)| len == 1));
    assert!(numbers.windows(2).all(|w| w[1].0 == w[0].0 + 1));

    // The ClientHello: its start and end in the first packet, the middle in the second
    let first = &initials[0].1[0];
    let second = &initials[1].1[0];
    let hello = client_hello([first, second].into_iter());
    let len = hello.len() as u64;
    assert!(
        len > 1250,
        "ClientHello of {len} bytes fits into one packet"
    );
    let head = coverage(first);
    assert_eq!(head.len(), 2);
    assert_eq!(head[0].0, 0);
    assert!((55..87).contains(&head[0].1));
    assert_eq!(head[1].1, len);
    assert_eq!(coverage(second), [(head[0].1, head[1].0)]);
    for packet in [first, second] {
        assert!((2..=10).contains(&packet.pings()), "{packet:?}");
    }

    // One counter for all packet number spaces
    let conn = pair.client_conn_mut(client_ch);
    let sent = conn.stats().path.sent_packets;
    assert_eq!(conn.shared_packet_number(), Some(1 + sent));
    // No early key update
    assert!(!conn.key_phase());
}

#[test]
fn firefox_like_client() {
    let _guard = subscribe();
    let mut pair = pair(firefox_endpoint());
    let (client_ch, server_ch) = pair.connect_with(browser_config(firefox_transport(321)));
    exchange(&mut pair, client_ch, server_ch);
    assert!(!pair.client_conn_mut(client_ch).is_closed());

    let datagrams = decode_all(pair.client.sent_datagrams.as_ref().unwrap());
    for (len, packets) in &datagrams {
        if matches!(packets[0], Packet::Initial { .. }) {
            assert_eq!(*len, 1252);
            // Padding goes after the last packet unless that is an ack-eliciting 1-RTT packet
            match packets.last().unwrap() {
                Packet::Zeros(_) => {}
                Packet::Other { first_byte, .. } => assert_eq!(first_byte & 0x80, 0),
                p => panic!("unpadded Initial datagram ending in {p:?}"),
            }
        }
        assert!(*len <= 1252);
    }

    // SNI slicing: the ClientHello is cut in the middle of the server name, the part after the
    // cut goes first, and both parts are shortened so that the ClientHello fills two packets
    // equally. rustls shuffles its extensions, so the server name may come early or late.
    let (_, first) = &datagrams[0];
    let (_, second) = &datagrams[1];
    let hello = client_hello([&first[0], &second[0]].into_iter());
    let len = hello.len();
    let name = hello
        .windows(9)
        .position(|w| w == b"localhost")
        .expect("server name");
    let mid = name + 4;
    let limit = len / len.div_ceil(1252 - 16);
    let (left, right) = if mid <= limit {
        (0..mid, mid + len - limit..len)
    } else {
        (0..limit - (len - mid), mid..len)
    };
    assert_matches!(
        &first[..],
        [
            Packet::Initial {
                pn: 321,
                pn_len: 2,
                ..
            },
            Packet::Zeros(_)
        ]
    );
    let crypto = first[0]
        .crypto()
        .iter()
        .map(|(offset, data)| (*offset as usize, data.len()))
        .collect::<Vec<_>>();
    assert_eq!(
        crypto,
        [(right.start, right.len()), (left.start, left.len())]
    );
    assert_matches!(
        &second[0],
        Packet::Initial {
            pn: 322,
            pn_len: 2,
            ..
        }
    );
    assert_eq!(
        coverage(&second[0]),
        [(left.end as u64, right.start as u64)]
    );
    assert_matches!(second.last(), Some(Packet::Zeros(_)));

    // The random first packet number is below 1024 and nothing is skipped
    let numbers = datagrams
        .iter()
        .flat_map(|(_, p)| p)
        .filter_map(|p| match p {
            Packet::Initial { pn, .. } => Some(*pn),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(numbers.windows(2).all(|w| w[1] == w[0] + 1));

    // The connection works with the advertised flow control windows and connection ID limit
    let conn = pair.client_conn_mut(client_ch);
    assert_eq!(conn.remote_cid_capacity(), 8);
    assert!(!conn.key_phase());
}

/// neqo's first Initial packet number: 1 to 1024, mostly below 33
fn neqo_first_pn(rng: &mut dyn rand::RngCore) -> u64 {
    let mut r = [0; 2];
    rng.fill_bytes(&mut r);
    1 + u64::from(r[0] & 0x1f) + (u64::from(r[1].saturating_sub(224)) << 5)
}

#[test]
fn random_first_packet_number() {
    let _guard = subscribe();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        let mut pair = pair(firefox_endpoint());
        let mut transport = firefox_transport(0);
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.packet_numbering(PacketNumbering::Sequential {
            first_initial: FirstPacketNumber::Random(Arc::new(neqo_first_pn)),
        });
        transport.fingerprint(fingerprint);
        let (client_ch, _) = pair.connect_with(browser_config(transport));
        assert!(!pair.client_conn_mut(client_ch).is_closed());
        let datagrams = decode_all(pair.client.sent_datagrams.as_ref().unwrap());
        let Packet::Initial { pn, pn_len, .. } = datagrams[0].1[0] else {
            panic!("first packet is not an Initial");
        };
        assert!((1..=1024).contains(&pn));
        // neqo's length rule: covering pn + 1 while nothing is acknowledged
        assert_eq!(pn_len, if pn + 1 < 256 { 1 } else { 2 });
        seen.insert(pn);
    }
    assert!(seen.len() > 1);
}

/// Resumption with 0-RTT data, returning the client's datagrams of the second connection
fn zero_rtt(
    endpoint: EndpointConfig,
    transport: impl Fn() -> TransportConfig,
) -> Vec<(usize, Vec<Packet>)> {
    let mut pair = pair(endpoint);
    zero_rtt_with(&mut pair, browser_config(transport()), false);
    decode_all(pair.client.sent_datagrams.as_ref().unwrap())
}

/// Resumption with 0-RTT data on `pair`, returning the handles of the second connection
///
/// With `settle`, the new connection sends its first flight and handles its endpoint events before
/// the application writes its 0-RTT data, as happens in practice.
fn zero_rtt_with(
    pair: &mut Pair,
    config: ClientConfig,
    settle: bool,
) -> (ConnectionHandle, ConnectionHandle) {
    pair.server.handle_incoming = Box::new(validate_incoming);

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
    pair.client.sent_datagrams = Some(Vec::new());
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    if settle {
        pair.drive_client();
    }
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"Hello, 0-RTT!";
    pair.client_send(client_ch, s).write(MSG).unwrap();
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    let server_ch = pair.server.assert_accept();
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MSG
    );
    let _ = chunks.finalize();
    (client_ch, server_ch)
}

#[test]
fn chrome_like_zero_rtt() {
    let _guard = subscribe();
    let datagrams = zero_rtt(chrome_endpoint(), chrome_transport);
    // The server's Initial carries one ack-eliciting packet, whose acknowledgement is not due yet
    // when the Finished is sent and the Initial keys are discarded
    assert!(
        datagrams
            .iter()
            .all(|(_, p)| !matches!(&p[0], Packet::Initial { frames, .. } if frames.contains(&Frame::Ack))),
        "{datagrams:?}"
    );
    // 0-RTT packets travel alone, after the full-size Initial packets
    let zero_rtt = datagrams
        .iter()
        .position(|(_, p)| p[0].is_0rtt())
        .expect("0-RTT packet");
    assert!(
        datagrams[..zero_rtt]
            .iter()
            .all(|(len, p)| *len == 1250 && p.len() == 1)
    );
    assert_eq!(datagrams[zero_rtt].1.len(), 1);
}

#[test]
fn firefox_like_zero_rtt() {
    let _guard = subscribe();
    let datagrams = zero_rtt(firefox_endpoint(), || firefox_transport(5));
    // The last Initial of the ClientHello shares its datagram with the first 0-RTT packet, and
    // the datagram is padded with zeros
    let (len, packets) = datagrams
        .iter()
        .find(|(_, p)| p.iter().any(Packet::is_0rtt))
        .expect("0-RTT packet");
    assert_eq!(*len, 1252);
    assert_matches!(
        &packets[..],
        [
            Packet::Initial { .. },
            Packet::Other { .. },
            Packet::Zeros(_)
        ]
    );
}

/// quiche's ACK decimation: every tenth packet once more than 100 have been received
#[test]
fn ack_decimation() {
    let _guard = subscribe();
    let mut thresholds = Vec::new();
    for decimation in [None, Some(AckDecimation::default())] {
        let mut pair = Pair::default();
        let mut transport = TransportConfig::default();
        let mut fingerprint = FingerprintConfig::default();
        fingerprint.ack_decimation(decimation);
        transport.fingerprint(fingerprint);
        let mut config = client_config();
        config.transport_config(Arc::new(transport));
        let (client_ch, server_ch) = pair.connect_with(config);
        let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
        let data = vec![0; 1_000_000];
        let mut written = 0;
        while written < data.len() {
            written += pair
                .server_send(server_ch, s)
                .write(&data[written..])
                .unwrap_or(0);
            pair.drive();
            let _ = pair.client_streams(client_ch).accept(Dir::Uni);
            let mut recv = pair.client_recv(client_ch, s);
            if let Ok(mut chunks) = recv.read(false) {
                while let Ok(Some(_)) = chunks.next(usize::MAX) {}
                let _ = chunks.finalize();
            };
        }
        let conn = pair.client_conn_mut(client_ch);
        assert!(conn.stats().udp_rx.datagrams > 500);
        thresholds.push(conn.ack_eliciting_threshold());
    }
    // An ACK after more than this many ack-eliciting packets
    assert_eq!(thresholds, [1, 9]);
}

/// Separate stream windows are advertised and enforced per stream class
#[test]
fn stream_receive_windows() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut transport = TransportConfig::default();
    transport
        .stream_receive_window_bidi_local(Some(1000u32.into()))
        .stream_receive_window_bidi_remote(Some(2000u32.into()))
        .stream_receive_window_uni(Some(3000u32.into()));
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let (client_ch, server_ch) = pair.connect_with(config);

    let data = [0; 10_000];
    // Opened by the client: the server may send `bidi_local`
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(b"x").unwrap();
    pair.drive();
    assert_matches!(pair.server_streams(server_ch).accept(Dir::Bi), Some(_));
    assert_eq!(pair.server_send(server_ch, s).write(&data), Ok(1000));
    // Opened by the server
    let s = pair.server_streams(server_ch).open(Dir::Bi).unwrap();
    assert_eq!(pair.server_send(server_ch, s).write(&data), Ok(2000));
    let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
    assert_eq!(pair.server_send(server_ch, s).write(&data), Ok(3000));
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// A certificate with enough names that the server's Handshake flight spans three datagrams, as
/// www.google.com's does
fn large_certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let names = (0..40)
        .map(|i| format!("host-{i:02}.{}.localhost", "x".repeat(30)))
        .chain(["localhost".to_owned()])
        .collect::<Vec<_>>();
    let key = rcgen::generate_simple_self_signed(names).unwrap();
    (
        key.cert.der().clone(),
        PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into()),
    )
}

/// A pair whose server presents [`large_certificate`], and a client configuration trusting it
fn pair_with_large_certificate(
    endpoint: EndpointConfig,
    transport: TransportConfig,
    google_numbering: bool,
) -> (Pair, ClientConfig) {
    let (cert, key) = large_certificate();
    let server = server_crypto_inner(Some((cert.clone(), key)), Some(vec![alpn()[7].clone()]));
    let pair = pair_with_server(endpoint, server, google_numbering);
    let mut config = ClientConfig::new(Arc::new(client_crypto_inner(
        Some(vec![cert]),
        Some(alpn()),
    )));
    config
        .transport_config(Arc::new(transport))
        .initial_dst_cid_provider(Arc::new(|| {
            RandomConnectionIdGenerator::new(8).generate_cid()
        }));
    (pair, config)
}

/// Chrome's acknowledgements during the handshake: none for the server's single ack-eliciting
/// Initial packet, and a Finished that carries the acknowledgement of the Handshake packets
#[test]
fn chrome_like_handshake_acks() {
    let _guard = subscribe();
    for policy in [AckPolicy::Quiche, AckPolicy::Standard] {
        let mut transport = chrome_transport();
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.ack_policy(policy);
        transport.fingerprint(fingerprint);
        let (mut pair, config) = pair_with_large_certificate(chrome_endpoint(), transport, true);
        let (client_ch, _) = pair.connect_with(config);
        let packets = sent_packets(&mut pair, client_ch);
        let initial_acks = packets
            .iter()
            .filter(|p| p.space == SpaceId::Initial && p.is_ack_only())
            .count();
        let finished = packets
            .iter()
            .find(|p| p.space == SpaceId::Handshake && p.has(&F::Crypto))
            .unwrap();
        match policy {
            AckPolicy::Quiche => {
                assert_eq!(initial_acks, 0, "{packets:#?}");
                assert!(finished.ack().is_some(), "{finished:?}");
            }
            AckPolicy::Standard => assert_eq!(initial_acks, 1, "{packets:#?}"),
        }
    }
}

/// quiche acknowledges Initial and Handshake packets 1 ms after the first unacknowledged one, or
/// at once after the second, and does not acknowledge the first 1-RTT packet at once
#[test]
fn quiche_handshake_ack_delay() {
    let _guard = subscribe();
    for policy in [AckPolicy::Quiche, AckPolicy::Standard] {
        let mut transport = chrome_transport();
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.ack_policy(policy);
        transport.fingerprint(fingerprint);
        let (mut pair, config) = pair_with_large_certificate(chrome_endpoint(), transport, true);
        // Enough latency that no probe timeout fires while the flight trickles in
        pair.latency = Duration::from_millis(50);
        let client_ch = pair.begin_connect(config);
        pair.drive_client();
        pair.time += pair.latency;
        pair.drive_server();
        // The server's flight arrives one datagram every 5 ms
        let gap = Duration::from_millis(5);
        let arrivals = pair
            .client
            .inbound
            .iter_mut()
            .enumerate()
            .map(|(i, datagram)| {
                datagram.0 += gap * i as u32;
                datagram.0
            })
            .collect::<Vec<_>>();
        assert!(
            arrivals.len() >= 3,
            "server flight of {} datagrams",
            arrivals.len()
        );
        // The last datagram only carries the server's first 1-RTT packet
        assert_eq!(pair.client.inbound.back().unwrap().2[0] & 0x80, 0);
        let first_1rtt = arrivals[arrivals.len() - 1];
        pair.drive();
        let packets = sent_packets(&mut pair, client_ch);
        let ack_only_times = packets
            .iter()
            .filter(|p| p.space != SpaceId::Data && p.is_ack_only())
            .map(|p| (p.space, p.time))
            .collect::<Vec<_>>();
        let first_1rtt_ack = packets
            .iter()
            .find(|p| p.is_1rtt() && p.ack().is_some())
            .unwrap();

        let ms = Duration::from_millis(1);
        match policy {
            AckPolicy::Quiche => {
                // Initial and Handshake packets of the first datagram, then the second Handshake
                // datagram, each acknowledged after 1 ms; the Finished acknowledges the third
                assert_eq!(
                    ack_only_times,
                    [
                        (SpaceId::Initial, arrivals[0] + ms),
                        (SpaceId::Handshake, arrivals[0] + ms),
                        (SpaceId::Handshake, arrivals[1] + ms),
                    ]
                );
                // The server's first 1-RTT packet, whose number follows a gap, is acknowledged
                // after max_ack_delay
                assert_eq!(first_1rtt_ack.time, first_1rtt + Duration::from_millis(25));
            }
            AckPolicy::Standard => {
                assert_eq!(
                    ack_only_times,
                    [
                        (SpaceId::Initial, arrivals[0]),
                        (SpaceId::Handshake, arrivals[0]),
                        (SpaceId::Handshake, arrivals[1]),
                    ]
                );
                assert_eq!(first_1rtt_ack.time, first_1rtt);
            }
        }
    }
}

/// quiche adds a pending acknowledgement to whatever it sends, and its PING packets look like
/// `PADDING(2) PING` (29 bytes) or `ACK PING`
#[test]
fn chrome_like_bundling_and_ping() {
    let _guard = subscribe();
    let mut pair = pair_with_server(
        chrome_endpoint(),
        server_crypto_with_alpn(vec![alpn()[7].clone()]),
        true,
    );
    let (client_ch, server_ch) = pair.connect_with(browser_config(chrome_transport()));
    pair.client_conn_mut(client_ch).clear_sent_log();

    // A lone PING: padding in front, only as much as header protection needs
    pair.client_conn_mut(client_ch).ping();
    pair.drive_client();
    let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
    let ping = Sent::new(log.last().unwrap().clone());
    assert_eq!(ping.frames, [F::Padding(2), F::Ping]);
    assert_eq!(ping.len, 29);
    pair.drive();

    // One packet from the server makes an acknowledgement pending, but not due
    let s = pair.server_streams(server_ch).open(Dir::Bi).unwrap();
    pair.server_send(server_ch, s).write(b"push").unwrap();
    pair.drive_server();
    pair.drive_client();
    let sent_before = pair.client_conn_mut(client_ch).sent_log().len();
    let _ = pair.client_streams(client_ch).accept(Dir::Bi);
    // The next packet the client sends carries it along
    pair.client_send(client_ch, s).write(b"request").unwrap();
    pair.drive_client();
    let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
    assert_eq!(log.len(), sent_before + 1);
    let request = Sent::new(log.last().unwrap().clone());
    assert!(
        matches!(request.frames[..], [F::Ack(_), F::Stream(_)]),
        "{request:?}"
    );
    pair.drive();

    // And so does a PING, which goes last
    pair.server_send(server_ch, s).write(b"push").unwrap();
    pair.drive_server();
    pair.drive_client();
    pair.client_conn_mut(client_ch).ping();
    pair.drive_client();
    let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
    let ping = Sent::new(log.last().unwrap().clone());
    assert!(matches!(ping.frames[..], [F::Ack(_), F::Ping]), "{ping:?}");
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// quiche adds a MAX_DATA frame to the 20th ACK-only packet in a row
#[test]
fn chrome_like_max_data_after_ack_only_packets() {
    let _guard = subscribe();
    let mut pair = pair(chrome_endpoint());
    let (client_ch, server_ch) = pair.connect_with(browser_config(chrome_transport()));
    // The first response raises the local limit by what has been read, too little to announce
    exchange(&mut pair, client_ch, server_ch);
    // A longer one makes the client send more runs of ACK-only packets
    let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
    let data = vec![0; 1_000_000];
    let mut written = 0;
    while written < data.len() {
        written += pair
            .server_send(server_ch, s)
            .write(&data[written..])
            .unwrap_or(0);
        pair.drive();
        let _ = pair.client_streams(client_ch).accept(Dir::Uni);
        let mut recv = pair.client_recv(client_ch, s);
        if let Ok(mut chunks) = recv.read(false) {
            while let Ok(Some(_)) = chunks.next(usize::MAX) {}
            let _ = chunks.finalize();
        };
    }
    let packets = sent_packets(&mut pair, client_ch);
    let mut run = 0;
    let mut max_data = 0;
    for packet in packets.iter().filter(|p| p.is_1rtt()) {
        if packet.is_ack_only() {
            run += 1;
            assert!(run <= 19, "{packets:#?}");
        } else {
            if packet.frames.iter().any(|f| matches!(f, F::MaxData(_)))
                && !packet.has_stream_frame()
            {
                assert_eq!(run, 19);
                // The limit advertised last, as Chrome repeats it (15728640, the initial
                // window), although reading has raised the local limit since
                assert_eq!(
                    packet.frames[..],
                    [
                        F::Ack(packet.ack().unwrap().to_vec()),
                        F::MaxData(15_728_640)
                    ]
                );
                max_data += 1;
            }
            run = 0;
        }
    }
    assert!(max_data > 0);
}

/// Datagrams processed together are acknowledged as if each had been answered on its own
#[test]
fn ack_each_datagram() {
    let _guard = subscribe();
    let mut counts = Vec::new();
    for enabled in [true, false] {
        let mut transport = firefox_transport(1);
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.ack_each_datagram(enabled);
        transport.fingerprint(fingerprint);
        let mut pair = pair_with_server(
            firefox_endpoint(),
            server_crypto_with_alpn(vec![alpn()[7].clone()]),
            true,
        );
        let (client_ch, server_ch) = pair.connect_with(browser_config(transport));
        pair.client_conn_mut(client_ch).clear_sent_log();
        // One burst of ten 1-RTT packets
        let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
        pair.server_send(server_ch, s).write(&[0; 12_000]).unwrap();
        pair.drive_server();
        let burst = pair.client.inbound.len();
        assert!(burst >= 8, "burst of {burst}");
        pair.drive_client();
        let acks = pair
            .client_conn_mut(client_ch)
            .sent_log()
            .to_vec()
            .into_iter()
            .map(Sent::new)
            .filter_map(|p| p.ack().map(|ranges| *ranges[0].end()))
            .collect::<Vec<_>>();
        counts.push((burst, acks));
    }
    // Every second packet, as neqo acknowledges them
    let (burst, acks) = &counts[0];
    assert_eq!(acks.len(), burst / 2, "{acks:?}");
    assert!(acks.windows(2).all(|w| w[1] == w[0] + 2), "{acks:?}");
    // One acknowledgement for the whole burst
    assert_eq!(counts[1].1.len(), 1);
}

/// neqo's first flight: one acknowledgement per server datagram, then the Finished together with
/// a 1-RTT packet that carries the NEW_CONNECTION_ID frame
#[test]
fn firefox_like_handshake() {
    let _guard = subscribe();
    let (mut pair, config) =
        pair_with_large_certificate(firefox_endpoint(), firefox_transport(321), true);
    let client_ch = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    // Datagrams of the server's flight that carry Initial or Handshake packets
    let server_datagrams = pair
        .client
        .inbound
        .iter()
        .filter(|(_, _, datagram)| datagram[0] & 0x80 != 0)
        .count();
    assert!(server_datagrams >= 3);
    pair.drive();
    let datagrams = sent_datagrams(&mut pair, client_ch);
    let handshake = datagrams
        .iter()
        .filter(|(_, p)| p.iter().any(|p| p.space == SpaceId::Handshake))
        .collect::<Vec<_>>();
    // Every server datagram but the last is acknowledged on its own; the first one carried the
    // server's Initial, so its acknowledgement shares a zero-padded datagram with the Initial one
    assert_eq!(handshake.len(), server_datagrams);
    let (len, first) = handshake[0];
    assert_eq!(*len, 1252);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|p| p.is_ack_only()));
    assert_eq!(first[0].space, SpaceId::Initial);
    for (_, packets) in &handshake[1..server_datagrams - 1] {
        assert_matches!(&packets[..], [p] if p.space == SpaceId::Handshake && p.is_ack_only());
    }
    // The Finished and the first 1-RTT packet: ACK, then NEW_CONNECTION_ID
    let (_, last) = handshake[server_datagrams - 1];
    assert_eq!(last.len(), 2);
    assert!(last[0].has(&F::Crypto) && last[0].ack().is_some());
    assert!(last[1].is_1rtt());
    assert!(
        matches!(last[1].frames[..], [F::Ack(_), F::NewConnectionId(1), ..]),
        "{:?}",
        last[1]
    );
}

/// neqo puts its NEW_CONNECTION_ID into the first 0-RTT packet, before any STREAM frame
#[test]
fn firefox_like_zero_rtt_connection_id() {
    let _guard = subscribe();
    let mut pair = pair(firefox_endpoint());
    let (client_ch, _) = zero_rtt_with(&mut pair, browser_config(firefox_transport(5)), false);
    let datagrams = sent_datagrams(&mut pair, client_ch);
    let first = datagrams
        .iter()
        .flat_map(|(_, p)| p)
        .find(|p| p.zero_rtt)
        .unwrap();
    assert!(
        matches!(first.frames[..], [F::NewConnectionId(1), F::Stream(_), ..]),
        "{first:?}"
    );
    // The response to the server's flight, as Firefox sends it: Initial ACK, Handshake ACK and
    // Finished, zero-padded like everything that carries an Initial packet. The acknowledgement of
    // the server's 1-RTT packet follows on its own.
    let (len, response) = datagrams
        .iter()
        .find(|(_, p)| p.iter().any(|p| p.space == SpaceId::Handshake))
        .unwrap();
    assert_eq!(*len, 1252);
    assert_eq!(
        response.iter().map(|p| p.space).collect::<Vec<_>>(),
        [SpaceId::Initial, SpaceId::Handshake]
    );
    assert!(response[0].is_ack_only());
    assert!(response[1].has(&F::Crypto));
}

/// Leading padding stays at least 22 bytes above the local connection ID length
#[test]
fn leading_padding() {
    let _guard = subscribe();
    for (cid_len, padding, expected) in [
        (
            0,
            PacketPadding::Leading,
            (vec![F::Padding(2), F::Ping], 29),
        ),
        (
            8,
            PacketPadding::Leading,
            (vec![F::Padding(3), F::Ping], 30),
        ),
        (
            0,
            PacketPadding::Standard,
            (vec![F::Ping, F::Padding(3)], 30),
        ),
    ] {
        let mut endpoint = EndpointConfig::default();
        endpoint.cid_generator(move || Box::new(RandomConnectionIdGenerator::new(cid_len)));
        let mut pair = pair(endpoint);
        let mut fingerprint = FingerprintConfig::default();
        fingerprint.packet_padding(padding);
        let mut transport = TransportConfig::default();
        transport.fingerprint(fingerprint);
        let (client_ch, _) = pair.connect_with(browser_config(transport));
        pair.client_conn_mut(client_ch).ping();
        pair.drive_client();
        let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
        let ping = Sent::new(log.last().unwrap().clone());
        assert_eq!(
            (ping.frames, ping.len),
            expected,
            "local CID of {cid_len} bytes"
        );
        pair.drive();
        assert!(!pair.client_conn_mut(client_ch).is_closed());
    }
}

/// A connection ID issued early survives the rejection of the 0-RTT packet that carried it
#[test]
fn early_connection_id_after_zero_rtt_rejection() {
    let _guard = subscribe();
    let mut pair = pair_with_server(
        firefox_endpoint(),
        server_crypto_with_alpn(vec!["foo".into(), "bar".into()]),
        false,
    );
    let mut client_crypto = Arc::new(client_crypto_with_alpn(vec!["foo".into()]));
    let mut config = ClientConfig::new(client_crypto.clone());
    config.transport_config(Arc::new(firefox_transport(5)));
    let client_ch = pair.begin_connect(config);
    pair.drive();
    pair.server.assert_accept();
    let now = pair.time;
    pair.client_conn_mut(client_ch)
        .close(now, VarInt(0), [][..].into());
    pair.drive();
    pair.client.connections.clear();
    pair.server.connections.clear();

    // Other protocols invalidate 0-RTT
    let this = Arc::get_mut(&mut client_crypto).unwrap();
    Arc::get_mut(&mut this.inner).unwrap().alpn_protocols = vec!["bar".into()];
    let mut config = ClientConfig::new(client_crypto);
    config.transport_config(Arc::new(firefox_transport(5)));
    pair.client.sent_datagrams = Some(Vec::new());
    let client_ch = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    pair.drive_client();
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, s).write(b"0-RTT").unwrap();
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).accepted_0rtt());
    pair.server.assert_accept();

    let packets = sent_packets(&mut pair, client_ch);
    let sent_in = |zero_rtt: bool| {
        packets
            .iter()
            .filter(|p| p.space == SpaceId::Data && p.zero_rtt == zero_rtt)
            .flat_map(|p| &p.frames)
            .any(|f| *f == F::NewConnectionId(1))
    };
    assert!(sent_in(true));
    assert!(sent_in(false), "{packets:#?}");
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// With a session that verifies the certificate asynchronously, Chrome's pattern: the Handshake
/// packets are acknowledged first, the Finished follows alone once verification is done, the
/// HTTP/3 control stream goes out alone, and the server's 1-RTT packet that arrived in the
/// meantime is acknowledged with the request
#[test]
fn chrome_like_async_verification() {
    use super::async_handshake::{Gate, GatedClientConfig, connect_until_waiting};

    let _guard = subscribe();
    for processing in [
        BufferedPacketProcessing::AfterFirst1rttData,
        BufferedPacketProcessing::Immediate,
    ] {
        let mut pair = pair_with_server(
            chrome_endpoint(),
            server_crypto_with_alpn(vec![alpn()[7].clone()]),
            true,
        );
        pair.latency = Duration::from_millis(10);
        let gate = Arc::new(Gate::default());
        let mut transport = chrome_transport();
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.buffered_packet_processing(processing);
        transport.fingerprint(fingerprint);
        let mut config = ClientConfig::new(Arc::new(GatedClientConfig {
            inner: Arc::new(client_crypto_with_alpn(alpn())),
            gate: gate.clone(),
        }));
        config
            .transport_config(Arc::new(transport))
            .initial_dst_cid_provider(Arc::new(|| {
                RandomConnectionIdGenerator::new(8).generate_cid()
            }));
        let (client_ch, arrival) = connect_until_waiting(&mut pair, config, &gate);
        // quiche's acknowledgement delay for Handshake packets passes
        pair.time += Duration::from_millis(1);
        pair.drive_client();
        pair.time = arrival + Duration::from_millis(5);
        gate.open(None);
        pair.drive_client();
        // The application writes the control stream, then a request
        let control = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
        pair.client_send(client_ch, control)
            .write(b"settings")
            .unwrap();
        pair.drive_client();
        let request = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
        pair.client_send(client_ch, request).write(b"GET").unwrap();
        pair.client_send(client_ch, request).finish().unwrap();
        pair.drive_client();
        pair.drive();
        pair.server.assert_accept();

        let packets = sent_packets(&mut pair, client_ch);
        let handshake = packets
            .iter()
            .filter(|p| p.space == SpaceId::Handshake)
            .collect::<Vec<_>>();
        assert!(handshake[0].is_ack_only(), "{handshake:?}");
        assert!(handshake[0].time < arrival + Duration::from_millis(5));
        let finished = handshake.iter().find(|p| p.has(&F::Crypto)).unwrap();
        assert_eq!(finished.frames, [F::Crypto]);
        assert_eq!(finished.time, arrival + Duration::from_millis(5));
        let streams = packets
            .iter()
            .filter(|p| p.is_1rtt() && p.has_stream_frame())
            .collect::<Vec<_>>();
        match processing {
            BufferedPacketProcessing::AfterFirst1rttData => {
                // As Chrome sends it: pn6 [STREAM(2)], pn8 [ACK STREAM(2) STREAM(10) STREAM(0)]
                assert_eq!(streams[0].frames, [F::Stream(control)], "{packets:#?}");
                assert!(
                    matches!(streams[1].frames[..], [F::Ack(_), F::Stream(id)] if id == request)
                );
            }
            BufferedPacketProcessing::Immediate => {
                // The control stream carries the acknowledgement
                assert!(
                    matches!(streams[0].frames[..], [F::Ack(_), F::Stream(id)] if id == control)
                );
            }
        }
        // No probe was needed; Initial packets carry chaos protection's PING frames
        assert!(
            packets
                .iter()
                .all(|p| p.space == SpaceId::Initial || !p.has(&F::Ping)),
            "{packets:#?}"
        );
        // The Finished and the control stream became ready at different moments, so they travel
        // in datagrams of their own even though packets are coalesced, as with Chrome
        let datagrams = sent_datagrams(&mut pair, client_ch);
        for (_, packets) in &datagrams {
            if packets
                .iter()
                .any(|p| p.has(&F::Crypto) && p.space == SpaceId::Handshake || p.has_stream_frame())
            {
                assert_eq!(packets.len(), 1, "{datagrams:#?}");
            }
        }
        assert!(!pair.client_conn_mut(client_ch).is_closed());
    }
}

/// Server crypto whose session tickets do not allow 0-RTT, like Cloudflare's
fn server_crypto_without_early_data() -> crate::crypto::rustls::QuicServerConfig {
    let key =
        rustls::pki_types::PrivateKeyDer::Pkcs8(CERTIFIED_KEY.signing_key.serialize_der().into());
    let mut config =
        crate::crypto::rustls::QuicServerConfig::inner(vec![CERTIFIED_KEY.cert.der().clone()], key)
            .unwrap();
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![alpn()[7].clone()];
    config.try_into().unwrap()
}

/// A resumed handshake without 0-RTT on `pair`: returns the client's handle after the client
/// processed the server's flight, and when that flight arrived
fn resume_without_early_data(pair: &mut Pair, config: ClientConfig) -> (ConnectionHandle, Instant) {
    pair.latency = Duration::from_millis(10);
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
    pair.client.sent_datagrams = Some(Vec::new());
    let client_ch = pair.begin_connect(config);
    assert!(!pair.client_conn_mut(client_ch).has_0rtt());
    pair.drive_client();
    pair.time += pair.latency;
    pair.drive_server();
    pair.time += pair.latency;
    let arrival = pair.time;
    // The client processes the flight and transmits whatever is ready
    pair.drive_client();
    (client_ch, arrival)
}

/// A resumed handshake needs no certificate verification, so it completes while the client
/// processes the server's flight. quiche writes the HTTP/3 control stream as soon as 1-RTT keys
/// exist, within the same flush, and coalesces its reply: the Initial ACK, the Handshake packet
/// with the Finished and the 1-RTT packet with the control stream, in one datagram whose Initial
/// packet is padded to fill it. Quinn's application only gets the connection afterwards, so the
/// Finished waits for its first write.
#[test]
fn chrome_like_resumed_handshake() {
    let _guard = subscribe();
    // A server that sends its ServerHello in two Initial packets makes the Initial
    // acknowledgement due at once; the standard policy acknowledges this server's single Initial
    // packet at once as well
    for hold in [true, false] {
        let mut transport = chrome_transport();
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint
            .ack_policy(AckPolicy::Standard)
            .finished_with_first_data(hold);
        transport.fingerprint(fingerprint);
        let mut pair =
            pair_with_server(chrome_endpoint(), server_crypto_without_early_data(), false);
        let (client_ch, _) = resume_without_early_data(&mut pair, browser_config(transport));
        let sent_before_write = pair.client.sent_datagrams.as_ref().unwrap().len();
        // The application gets the connection and writes its control stream
        let control = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
        assert_eq!(control, StreamId::new(Side::Client, Dir::Uni, 0));
        pair.client_send(client_ch, control)
            .write(b"settings")
            .unwrap();
        pair.drive_client();

        let datagrams = sent_datagrams(&mut pair, client_ch);
        let reply_index = datagrams
            .iter()
            .position(|(_, p)| p.iter().any(|p| p.space == SpaceId::Handshake))
            .unwrap();
        // The first flight is unchanged: full-size Initial packets, one per datagram
        assert!(reply_index >= 1);
        assert!(
            datagrams[..reply_index]
                .iter()
                .all(|(len, p)| *len == 1250 && p.len() == 1 && p[0].space == SpaceId::Initial)
        );
        let (len, reply) = &datagrams[reply_index];
        assert_eq!(*len, 1250);
        // The Initial packet takes the padding
        assert_matches!(&reply[0].frames[..], [F::Ack(_), F::Padding(n)] if *n > 900);
        assert!(reply[1].ack().is_some() && reply[1].has(&F::Crypto));
        match hold {
            true => {
                // Nothing left before the application wrote
                assert_eq!(sent_before_write, reply_index);
                assert_eq!(
                    reply.iter().map(|p| p.space).collect::<Vec<_>>(),
                    [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data],
                    "{reply:#?}"
                );
                // With the acknowledgement of the server's 1-RTT packets, which quiche bundles
                assert!(reply[2].has(&F::Stream(control)), "{reply:#?}");
                assert_eq!(reply.iter().map(|p| p.len).sum::<usize>(), 1250);
            }
            false => {
                // The Finished left before the application could write
                assert!(
                    !reply.iter().any(|p| p.has(&F::Stream(control))),
                    "{reply:#?}"
                );
                assert!(
                    datagrams[reply_index + 1..]
                        .iter()
                        .any(|(_, p)| p.iter().any(|p| p.has(&F::Stream(control))))
                );
            }
        }
    }
}

/// A resumed Chrome-like connection whose server sends its Initial and Handshake packets in
/// datagrams of their own, the Handshake ones 1.5 ms after the Initial one. Returns the pair with
/// the client's handle, the number of datagrams of its first flight and when the handshake
/// completed; the client has not transmitted since.
fn resume_with_split_flight() -> (Pair, ConnectionHandle, usize, Instant) {
    let crypto = server_crypto_without_early_data();
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    let mut fingerprint = FingerprintConfig::default();
    fingerprint.coalesce_packets(false);
    let mut server_transport = TransportConfig::default();
    server_transport.fingerprint(fingerprint);
    server_config.transport_config(Arc::new(server_transport));
    let server = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server_config)),
        true,
        None,
    );
    let client = Endpoint::new(Arc::new(chrome_endpoint()), None, true, None);
    let mut pair = Pair::new_from_endpoint(client, server);
    pair.client.log_sent_packets = true;
    pair.latency = Duration::from_millis(10);

    let config = browser_config(chrome_transport());
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
    pair.client.sent_datagrams = Some(Vec::new());
    let client_ch = pair.begin_connect(config);
    pair.drive_client();
    pair.time += pair.latency;
    pair.drive_server();
    let arrival = pair.time + pair.latency;
    let completion = arrival + Duration::from_micros(1500);
    assert!(pair.client.inbound.len() >= 2);
    for (i, datagram) in pair.client.inbound.iter_mut().enumerate() {
        datagram.0 = if i == 0 { arrival } else { completion };
    }
    let server_addr = pair.server.addr;
    pair.time = arrival;
    pair.client.deliver_incoming(arrival, server_addr);
    pair.time = completion;
    pair.client.deliver_incoming(completion, server_addr);
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    let first_flight = pair.client.sent_datagrams.as_ref().unwrap().len();
    (pair, client_ch, first_flight, completion)
}

/// A server's flight that arrives in parts: when the handshake completes, the acknowledgement of
/// the first part is overdue already, and the Finished still waits for the application's first
/// write, for up to 0.5 ms
#[test]
fn chrome_like_resumed_handshake_split_flight() {
    let _guard = subscribe();
    let (mut pair, client_ch, first_flight, completion) = resume_with_split_flight();
    // The connection handles its due timers and transmits: nothing yet
    pair.client_conn_mut(client_ch).handle_timeout(completion);
    pair.drive_client();
    assert_eq!(
        pair.client.sent_datagrams.as_ref().unwrap().len(),
        first_flight
    );

    // The application writes its control stream 170 µs later
    pair.time += Duration::from_micros(170);
    let control = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, control)
        .write(b"settings")
        .unwrap();
    pair.drive_client();
    let datagrams = sent_datagrams(&mut pair, client_ch);
    let (len, reply) = &datagrams[first_flight];
    assert_eq!(*len, 1250);
    assert_eq!(
        reply.iter().map(|p| p.space).collect::<Vec<_>>(),
        [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data],
        "{reply:#?}"
    );
    assert_matches!(&reply[0].frames[..], [F::Ack(_), F::Padding(_)]);
    assert!(reply[1].ack().is_some() && reply[1].has(&F::Crypto));
    assert!(reply[2].has(&F::Stream(control)));

    // Without a write, the Finished goes out after 0.5 ms
    let (mut pair, client_ch, _, completion) = resume_with_split_flight();
    pair.drive();
    let packets = sent_packets(&mut pair, client_ch);
    let finished = packets
        .iter()
        .find(|p| p.space == SpaceId::Handshake && p.has(&F::Crypto))
        .unwrap();
    assert_eq!(finished.time, completion + Duration::from_micros(500));
}

/// The held Finished goes out on its own once the acknowledgements of the server's flight must
/// not wait any longer
#[test]
fn chrome_like_held_finished_is_bounded() {
    let _guard = subscribe();
    let mut transport = chrome_transport();
    let mut fingerprint = transport.fingerprint.clone();
    fingerprint.ack_policy(AckPolicy::Standard);
    transport.fingerprint(fingerprint);
    let mut pair = pair_with_server(chrome_endpoint(), server_crypto_without_early_data(), false);
    let (client_ch, arrival) = resume_without_early_data(&mut pair, browser_config(transport));
    pair.drive();
    let packets = sent_packets(&mut pair, client_ch);
    let finished = packets
        .iter()
        .find(|p| p.space == SpaceId::Handshake && p.has(&F::Crypto))
        .unwrap();
    // Initial and Handshake packets are acknowledged within 1 ms
    assert_eq!(finished.time, arrival + Duration::from_millis(1));
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// The kept 1-RTT packets are deferred the same way when the handshake completes while a packet
/// is processed, here a retransmission of the server that arrives after verification finished
#[test]
fn chrome_like_deferral_after_completion_in_packet_path() {
    use super::async_handshake::{Gate, GatedClientConfig, connect_until_waiting};

    let _guard = subscribe();
    let mut pair = pair_with_server(
        chrome_endpoint(),
        server_crypto_with_alpn(vec![alpn()[7].clone()]),
        true,
    );
    pair.latency = Duration::from_millis(10);
    let gate = Arc::new(Gate::default());
    let mut config = ClientConfig::new(Arc::new(GatedClientConfig {
        inner: Arc::new(client_crypto_with_alpn(alpn())),
        gate: gate.clone(),
    }));
    config
        .transport_config(Arc::new(chrome_transport()))
        .initial_dst_cid_provider(Arc::new(|| {
            RandomConnectionIdGenerator::new(8).generate_cid()
        }));
    let (client_ch, _) = connect_until_waiting(&mut pair, config, &gate);
    gate.open(None);
    // The server retransmits after a probe timeout; the client completes the handshake while it
    // processes the retransmission, before it polls the session
    pair.time = pair.server.next_wakeup().unwrap();
    pair.drive_server();
    // Only the first datagram, which completes the handshake; like quiche, the client processes
    // kept packets before later datagrams
    pair.client.inbound.truncate(1);
    pair.time += pair.latency;
    let kept = pair.client_conn_mut(client_ch).kept_1rtt_packets();
    pair.drive_client();
    assert!(!pair.client_conn_mut(client_ch).is_handshaking());
    // The server's first 1-RTT packet, kept during verification, waits for 1-RTT data
    assert!(kept > 0);
    assert_eq!(pair.client_conn_mut(client_ch).kept_1rtt_packets(), kept);

    let control = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    pair.client_send(client_ch, control)
        .write(b"settings")
        .unwrap();
    pair.drive_client();
    // Right after that transmission
    pair.drive_client();
    assert_eq!(pair.client_conn_mut(client_ch).kept_1rtt_packets(), 0);
    let packets = sent_packets(&mut pair, client_ch);
    let control_packet = packets
        .iter()
        .find(|p| p.is_1rtt() && p.has(&F::Stream(control)))
        .unwrap();
    assert!(control_packet.ack().is_none(), "{control_packet:?}");
    pair.drive();
    assert!(!pair.client_conn_mut(client_ch).is_closed());
}

/// Chrome's explicit close: a transport-level CONNECTION_CLOSE with NO_ERROR, frame type 0 and
/// the reason "70:net error"
#[test]
fn transport_close() {
    let _guard = subscribe();
    let mut pair = pair(chrome_endpoint());
    let (client_ch, server_ch) = pair.connect_with(browser_config(chrome_transport()));
    let now = pair.time;
    pair.client_conn_mut(client_ch).close_transport(
        now,
        TransportErrorCode::NO_ERROR,
        Some(VarInt(0)),
        Bytes::from_static(b"70:net error"),
    );
    pair.drive();

    let log = pair.client_conn_mut(client_ch).sent_log().to_vec();
    let close = log
        .iter()
        .flat_map(|p| frame::Iter::new(p.payload.clone()).unwrap())
        .find_map(|f| match f {
            Ok(frame::Frame::Close(close)) => Some(close),
            _ => None,
        })
        .expect("CONNECTION_CLOSE sent");
    assert_matches!(
        close,
        frame::Close::Connection(frame::ConnectionClose {
            error_code: TransportErrorCode::NO_ERROR,
            frame_type: None,
            ref reason,
        }) if &reason[..] == b"70:net error"
    );
    assert!(pair.client_conn_mut(client_ch).is_closed());
    let conn = pair.server_conn_mut(server_ch);
    let reason = std::iter::from_fn(|| conn.poll()).find_map(|event| match event {
        Event::ConnectionLost { reason } => Some(reason),
        _ => None,
    });
    assert_matches!(
        reason,
        Some(ConnectionError::ConnectionClosed(frame::ConnectionClose {
            error_code: TransportErrorCode::NO_ERROR,
            ..
        }))
    );
}

/// An abandoned connection sends nothing, drops what it has not sent and leaves the endpoint
#[test]
fn abandon_sends_nothing() {
    let _guard = subscribe();
    let mut pair = pair(chrome_endpoint());
    let (client_ch, server_ch) = pair.connect_with(browser_config(chrome_transport()));
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(b"request").unwrap();
    pair.drive_client();
    let sent = pair.client.sent_datagrams.as_ref().unwrap().len();
    // Unsent data is dropped
    pair.client_send(client_ch, s).write(b"never sent").unwrap();
    pair.client_conn_mut(client_ch).abandon();
    pair.drive();

    assert_eq!(pair.client.sent_datagrams.as_ref().unwrap().len(), sent);
    assert_eq!(pair.client.endpoint.open_connections(), 0);
    let conn = pair.client_conn_mut(client_ch);
    assert!(conn.is_drained());
    assert_matches!(
        conn.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::LocallyClosed
        })
    );
    // The server learns nothing and times out
    assert!(!pair.server_conn_mut(server_ch).is_closed());
    pair.time += Duration::from_secs(60);
    pair.drive_server();
    let conn = pair.server_conn_mut(server_ch);
    let reason = std::iter::from_fn(|| conn.poll()).find_map(|event| match event {
        Event::ConnectionLost { reason } => Some(reason),
        _ => None,
    });
    assert_matches!(reason, Some(ConnectionError::TimedOut));
}

/// Browsers send keep-alive PINGs only while requests are open; otherwise the connection times
/// out silently, although HTTP/3's unidirectional control stream stays open
#[test]
fn keep_alive_only_with_open_bidi_streams() {
    let _guard = subscribe();
    for request_open in [true, false] {
        let mut pair = pair(chrome_endpoint());
        let mut transport = chrome_transport();
        transport
            .max_idle_timeout(Some(VarInt(3_000).into()))
            .keep_alive_interval(Some(Duration::from_secs(1)))
            .keep_alive_only_with_open_bidi_streams(true);
        let (client_ch, server_ch) = pair.connect_with(browser_config(transport));
        let control = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
        pair.client_send(client_ch, control)
            .write(b"control")
            .unwrap();
        if request_open {
            let request = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
            pair.client_send(client_ch, request).write(b"GET").unwrap();
        }
        pair.drive();
        let _ = pair.server_streams(server_ch).accept(Dir::Uni);
        let _ = pair.server_streams(server_ch).accept(Dir::Bi);
        let pings = pair.client_conn_mut(client_ch).stats().frame_tx.ping;

        let end = pair.time + Duration::from_secs(10);
        while pair.time < end {
            if !pair.step() {
                match min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                    Some(time) => pair.time = time,
                    None => break,
                }
            }
        }
        let conn = pair.client_conn_mut(client_ch);
        let stats = conn.stats();
        if request_open {
            assert!(!conn.is_closed());
            assert!(stats.frame_tx.ping > pings);
        } else {
            // Silently timed out: no PING, no CONNECTION_CLOSE
            let events = std::iter::from_fn(|| conn.poll()).collect::<Vec<_>>();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    Event::ConnectionLost {
                        reason: ConnectionError::TimedOut
                    }
                )),
                "{events:?}"
            );
            assert_eq!(stats.frame_tx.ping, pings);
            assert_eq!(stats.frame_tx.connection_close, 0);
        }
    }
}

/// Out-of-range settings are reduced to values that cannot panic
#[test]
fn settings_are_clamped() {
    let _guard = subscribe();
    let rtt = Duration::from_millis(40);
    let max = Duration::from_millis(25);
    let mut decimation = AckDecimation::default();
    assert_eq!(decimation.rtt_fraction(f32::INFINITY).delay(rtt, max), max);
    assert_eq!(
        decimation.rtt_fraction(f32::NAN).delay(rtt, max),
        Duration::from_millis(1)
    );
    assert_eq!(
        decimation.rtt_fraction(-1.0).delay(rtt, max),
        Duration::from_millis(1)
    );
    assert_eq!(
        decimation.rtt_fraction(0.25).delay(rtt, max),
        Duration::from_millis(10)
    );

    for numbering in [
        PacketNumbering::Shared { first: u64::MAX },
        PacketNumbering::Sequential {
            first_initial: FirstPacketNumber::Fixed(u64::MAX),
        },
    ] {
        let mut pair = pair(chrome_endpoint());
        let mut transport = chrome_transport();
        let mut fingerprint = transport.fingerprint.clone();
        fingerprint.packet_numbering(numbering);
        transport.fingerprint(fingerprint);
        let (client_ch, server_ch) = pair.connect_with(browser_config(transport));
        exchange(&mut pair, client_ch, server_ch);
        let first = pair.client_conn_mut(client_ch).sent_log()[0].clone();
        assert_eq!(first.space, SpaceId::Initial);
        assert_eq!(first.number, crate::MAX_FIRST_PACKET_NUMBER);
    }
}

/// The browser framings bring their padding style, whatever `initial_padding` says
#[test]
fn framing_implies_padding() {
    let _guard = subscribe();
    // Chaos protection pads with PADDING frames, to 1200 bytes if no size is given
    let mut pair = pair(chrome_endpoint());
    let mut transport = chrome_transport();
    let mut fingerprint = transport.fingerprint.clone();
    fingerprint.initial_padding(InitialPadding::Standard);
    transport.fingerprint(fingerprint);
    let (client_ch, _) = pair.connect_with(browser_config(transport));
    let datagrams = sent_datagrams(&mut pair, client_ch);
    for (len, packets) in datagrams
        .iter()
        .filter(|(_, p)| p[0].space == SpaceId::Initial)
    {
        assert_eq!(*len, 1200);
        assert_eq!(packets.iter().map(|p| p.len).sum::<usize>(), 1200);
    }

    // SNI slicing appends zeros, even if PADDING frames were asked for
    let mut pair = self::pair(firefox_endpoint());
    let mut transport = firefox_transport(1);
    let mut fingerprint = transport.fingerprint.clone();
    fingerprint.initial_padding(InitialPadding::Frames { size: 1252 });
    transport.fingerprint(fingerprint);
    let (client_ch, _) = pair.connect_with(browser_config(transport));
    let datagrams = sent_datagrams(&mut pair, client_ch);
    let (len, packets) = &datagrams[0];
    assert_eq!(*len, 1252);
    assert!(packets.iter().map(|p| p.len).sum::<usize>() < 1252);
}

/// A pending acknowledgement has to leave `max_ack_delay` after the first 1-RTT packet it covers,
/// also once it is due: a driver that holds back transmission, such as quinn's transmit hold,
/// sends it then at the latest
#[test]
fn ack_deadline() {
    let _guard = subscribe();
    let max_ack_delay = Duration::from_millis(5);
    let mut transport = TransportConfig::default();
    transport.max_ack_delay(max_ack_delay);
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect_with(config);
    assert_eq!(pair.client_conn_mut(client_ch).ack_deadline(), None);

    let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
    let server = pair.server.addr;
    let first = pair.time;
    for data in [&b"a"[..], b"b"] {
        pair.server_send(server_ch, s).write(data).unwrap();
        pair.drive_server();
        let now = pair.time;
        pair.client.deliver_incoming(now, server);
        pair.time += Duration::from_millis(1);
    }
    // Due since the second packet, and still bound to the arrival of the first
    let deadline = pair.client_conn_mut(client_ch).ack_deadline();
    assert_eq!(deadline, Some(first + max_ack_delay));

    // Held until then, it goes out at that time
    let acks = pair.client_conn_mut(client_ch).stats().frame_tx.acks;
    pair.time = deadline.unwrap();
    pair.drive_client();
    assert_eq!(
        pair.client_conn_mut(client_ch).stats().frame_tx.acks,
        acks + 1
    );
    assert_eq!(pair.client_conn_mut(client_ch).ack_deadline(), None);
}

/// Initial and Handshake packets are acknowledged immediately, within the timer granularity
#[test]
fn ack_deadline_during_handshake() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    let (now, server) = (pair.time, pair.server.addr);
    pair.client.deliver_incoming(now, server);
    assert_eq!(
        pair.client_conn_mut(client_ch).ack_deadline(),
        Some(now + Duration::from_millis(1))
    );
}

/// Acknowledgements kept for later datagrams keep their deadline
#[test]
fn ack_deadline_of_kept_acknowledgements() {
    let _guard = subscribe();
    let mut pair = pair_with_server(
        firefox_endpoint(),
        server_crypto_with_alpn(vec![alpn()[7].clone()]),
        false,
    );
    let (client_ch, server_ch) = pair.connect_with(browser_config(firefox_transport(1)));
    let s = pair.server_streams(server_ch).open(Dir::Uni).unwrap();
    pair.server_send(server_ch, s).write(&[0; 12_000]).unwrap();
    pair.drive_server();
    // The datagrams of the burst arrive 1 ms apart, so that the acknowledgement of the first two
    // is kept when the third arrives
    let first = pair.time;
    for (i, datagram) in pair.client.inbound.iter_mut().enumerate() {
        datagram.0 = first + Duration::from_millis(i as u64);
    }
    pair.time = pair.client.inbound.back().unwrap().0;
    let (now, server) = (pair.time, pair.server.addr);
    pair.client.deliver_incoming(now, server);
    // Firefox advertises a max_ack_delay of 20 ms
    assert_eq!(
        pair.client_conn_mut(client_ch).ack_deadline(),
        Some(first + Duration::from_millis(20))
    );
}
