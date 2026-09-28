//! Compatible version negotiation (RFC 9368) between QUIC versions 1 and 2 (RFC 9369)
//!
//! A client offers the versions its first flight can be converted to in `version_information`.
//! A server that prefers one of them switches the connection to it right away: it answers the
//! client's first flight in the negotiated version, which the client learns from the version
//! field of the server's first Initial packet. Both sides check the peer's
//! `version_information` to detect a downgrade.

use super::*;
use crate::{
    QUIC_VERSION_2, coding::BufExt, config::VERSION_INFORMATION_ID,
    transport_parameters::VersionInformationParameter,
};

/// The version that a first flight of `version` can be converted to, if any
///
/// QUIC versions 1 and 2 are compatible with each other (RFC 9369, section 4).
pub(crate) fn compatible_version(version: u32) -> Option<u32> {
    match version {
        1 => Some(QUIC_VERSION_2),
        QUIC_VERSION_2 => Some(1),
        _ => None,
    }
}

/// State of the version negotiation of a connection
pub(super) struct VersionNegotiation {
    /// Version of the client's first flight
    original: u32,
    /// `version_information` this endpoint sent, if any
    sent: Option<VersionInformationParameter>,
    /// Client: whether the version can no longer change because the server sent handshake data
    locked: bool,
    /// Server: Initial keys of the original version while the connection uses another one
    original_initial_keys: Option<Keys>,
}

impl VersionNegotiation {
    pub(super) fn new(version: u32) -> Self {
        Self {
            original: version,
            sent: None,
            locked: false,
            original_initial_keys: None,
        }
    }
}

impl Connection {
    /// Record the outcome of the endpoint's version choice
    ///
    /// `original` is the version of the client's first flight and `sent` the `version_information`
    /// this endpoint sends. A server that switched to another version passes the Initial keys of
    /// `original`, which it keeps accepting until it discards its Initial keys.
    pub(crate) fn init_version_negotiation(
        &mut self,
        original: u32,
        sent: Option<VersionInformationParameter>,
        original_initial_keys: Option<Keys>,
    ) {
        self.version_negotiation = VersionNegotiation {
            original,
            sent,
            locked: false,
            original_initial_keys,
        };
    }

    /// The version other than the connection's whose long header packets are still processed
    pub(super) fn alternative_version(&self) -> Option<u32> {
        let negotiation = &self.version_negotiation;
        match self.side.side() {
            Side::Client => {
                if negotiation.locked
                    || self.version != negotiation.original
                    || !self.state.is_handshake()
                {
                    return None;
                }
                let version = compatible_version(self.version)?;
                negotiation.sent?.lists(version).then_some(version)
            }
            Side::Server => negotiation
                .original_initial_keys
                .as_ref()
                .map(|_| negotiation.original),
        }
    }

    /// Stop switching versions once the server has sent handshake data (RFC 9369, section 4.1)
    pub(super) fn lock_version(&mut self) {
        self.version_negotiation.locked = true;
    }

    /// Forget the original version's Initial keys together with the Initial keys
    pub(super) fn discard_original_initial_keys(&mut self) {
        self.version_negotiation.original_initial_keys = None;
    }

    /// The Initial keys of the client's first-flight version, kept if the server switched to
    /// another one (until [`Self::discard_original_initial_keys`]). `endpoint.rs` reuses this
    /// instead of re-deriving the same keys to close a connection whose handshake fails right
    /// after such a switch.
    pub(crate) fn original_initial_keys(&self) -> Option<&Keys> {
        self.version_negotiation.original_initial_keys.as_ref()
    }

    /// Handle a long header packet of another version than the connection's
    pub(super) fn handle_other_version(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let version = partial_decode.version();
        if version.is_none()
            || version != self.alternative_version()
            || !partial_decode.is_initial()
        {
            trace!("dropping packet of another QUIC version");
            return;
        }
        match self.side.side() {
            Side::Client => self.switch_version(now, remote, ecn, partial_decode),
            Side::Server => self.handle_original_initial(now, remote, ecn, partial_decode),
        }
    }

    /// Client: follow the server to the version of its Initial packet if the packet authenticates
    fn switch_version(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let original = self.version;
        // Only called by `handle_other_version` once it confirmed `partial_decode.is_initial()`,
        // which always carries a version.
        let version = partial_decode.version().unwrap();
        if self.crypto.set_version(version).is_err() {
            debug!("the crypto session cannot switch to version {version:#x}");
            self.fail_handshake(
                now,
                TransportError::VERSION_NEGOTIATION_ERROR("cannot switch to the server's version"),
            );
            return;
        }
        // Initial keys derive from the client's Destination Connection ID (RFC 9001, 5.2)
        let cid = self.retry_src_cid.unwrap_or(self.initial_dst_cid);
        let keys = self.crypto.initial_keys(&cid, Side::Client);
        let previous = self.spaces[SpaceId::Initial].crypto.replace(keys);
        let packet = packet_crypto::unprotect_header(partial_decode, &self.spaces, None, None)
            .and_then(|decoded| decoded.packet)
            .and_then(|mut packet| self.authenticates_initial(&mut packet).then_some(packet));
        let Some(packet) = packet else {
            trace!("dropping packet of version {version:#x} that does not authenticate");
            self.spaces[SpaceId::Initial].crypto = previous;
            if self.crypto.set_version(original).is_err() {
                self.fail_handshake(
                    now,
                    TransportError::INTERNAL_ERROR("crypto session cannot switch back"),
                );
            }
            return;
        };
        debug!("server switched to version {version:#x}");
        self.version = version;
        self.lock_version();
        // 0-RTT packets are only sent in the original version (RFC 9369, section 4.1)
        self.zero_rtt_crypto = None;
        // `authenticates_initial` already decrypted `packet` in place to check it; `handle_packet`
        // is told so, to not repeat the AEAD decrypt on the same bytes with the same keys.
        self.handle_packet(now, remote, ecn, Some(packet), false, true);
    }

    /// Decrypts an Initial packet in place with the current Initial keys, returning whether it
    /// authenticates. On failure the packet is dropped by the caller regardless, so leaving it
    /// partially decrypted is harmless; on success the caller reuses the now-decrypted payload
    /// instead of decrypting it again.
    fn authenticates_initial(&self, packet: &mut Packet) -> bool {
        let space = &self.spaces[SpaceId::Initial];
        let (Some(number), Some(crypto)) = (packet.header.number(), &space.crypto) else {
            return false;
        };
        crypto
            .packet
            .remote
            .decrypt(
                number.expand(space.rx_packet + 1),
                &packet.header_data,
                &mut packet.payload,
            )
            .is_ok()
    }

    /// Server: process an Initial packet of the original version after switching to another one
    fn handle_original_initial(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        let original_keys = self.version_negotiation.original_initial_keys.take();
        let keys = mem::replace(&mut self.spaces[SpaceId::Initial].crypto, original_keys);
        if let Some(decoded) = packet_crypto::unprotect_header(
            partial_decode,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.peer_params.stateless_reset_token,
        ) {
            self.handle_packet(
                now,
                remote,
                ecn,
                decoded.packet,
                decoded.stateless_reset,
                false,
            );
        }
        if self.spaces[SpaceId::Initial].crypto.is_some() {
            self.version_negotiation.original_initial_keys =
                mem::replace(&mut self.spaces[SpaceId::Initial].crypto, keys);
        }
    }

    /// Check the peer's `version_information` if this endpoint sent one
    pub(super) fn check_version_information(
        &self,
        params: &TransportParameters,
    ) -> Result<(), TransportError> {
        let negotiation = &self.version_negotiation;
        match negotiation.sent {
            Some(sent) => check_version_information(
                self.side.side(),
                &sent,
                negotiation.original,
                self.version,
                params.version_information.as_ref(),
            ),
            None => Ok(()),
        }
    }
}

/// Validate the `version_information` received by `side` (RFC 9368, section 4)
///
/// `original` is the version of the client's first flight, `negotiated` the connection's version.
pub(super) fn check_version_information(
    side: Side,
    sent: &VersionInformationParameter,
    original: u32,
    negotiated: u32,
    received: Option<&VersionInformationParameter>,
) -> Result<(), TransportError> {
    // Without a Version Negotiation packet, the handshake may complete without the parameter
    let Some(received) = received else {
        return Ok(());
    };
    if !received.is_valid() {
        return Err(TransportError::TRANSPORT_PARAMETER_ERROR(
            "malformed version_information",
        ));
    }
    let chosen = received.chosen();
    match side {
        Side::Server if chosen != original => Err(TransportError::VERSION_NEGOTIATION_ERROR(
            "the client's chosen version differs from the version of its first flight",
        )),
        Side::Client if chosen != negotiated || !sent.lists(chosen) => {
            Err(TransportError::VERSION_NEGOTIATION_ERROR(
                "the server's chosen version differs from the negotiated version",
            ))
        }
        _ => Ok(()),
    }
}

/// The version a server switches a new connection to
///
/// `original` is the version of the client's first Initial packet and `payload` its decrypted
/// payload; `supported` lists the server's versions by preference. The server switches if it
/// prefers the version compatible with `original` and the client offers it. It keeps `original`
/// if the packet does not hold the complete ClientHello, e.g. because post-quantum key shares
/// spread it over two packets, or if the client attempts 0-RTT, which is only accepted in the
/// original version.
pub(crate) fn negotiate_version(original: u32, payload: &[u8], supported: &[u32]) -> u32 {
    let Some(compatible) = compatible_version(original) else {
        return original;
    };
    let preferred = supported
        .iter()
        .find(|&&version| version == original || version == compatible);
    if preferred != Some(&compatible) {
        return original;
    }
    match client_version_information(payload) {
        Some(offer)
            if offer.is_valid() && offer.chosen() == original && offer.lists(compatible) =>
        {
            compatible
        }
        _ => original,
    }
}

/// The `version_information` in the ClientHello that the CRYPTO frames of `payload` carry
///
/// `None` if the frames do not hold the complete ClientHello, if the ClientHello attempts 0-RTT
/// or if it has no such parameter.
fn client_version_information(payload: &[u8]) -> Option<VersionInformationParameter> {
    let mut frames = Vec::new();
    for frame in frame::Iter::new(Bytes::copy_from_slice(payload)).ok()? {
        match frame {
            Ok(Frame::Crypto(crypto)) => frames.push(crypto),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    frames.sort_by_key(|crypto| crypto.offset);
    let mut hello = Vec::new();
    for crypto in frames {
        let Some(skip) = (hello.len() as u64).checked_sub(crypto.offset) else {
            break;
        };
        hello.extend_from_slice(<[u8]>::get(&crypto.data, skip as usize..).unwrap_or_default());
    }
    client_hello_version_information(&hello)
}

/// The `version_information` in the transport parameters of a TLS 1.3 ClientHello
fn client_hello_version_information(mut hello: &[u8]) -> Option<VersionInformationParameter> {
    fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (<[u8]>::get(r, ..n)?, <[u8]>::get(r, n..)?);
        *r = tail;
        Some(head)
    }
    fn uint(r: &mut &[u8], n: usize) -> Option<usize> {
        Some(take(r, n)?.iter().fold(0, |x, &b| x << 8 | usize::from(b)))
    }
    fn vector<'a>(r: &mut &'a [u8], len_bytes: usize) -> Option<&'a [u8]> {
        let len = uint(r, len_bytes)?;
        take(r, len)
    }

    // RFC 8446, section 4.1.2
    if uint(&mut hello, 1)? != 1 {
        return None;
    }
    let mut body = vector(&mut hello, 3)?;
    take(&mut body, 2 + 32)?; // legacy_version, random
    vector(&mut body, 1)?; // legacy_session_id
    vector(&mut body, 2)?; // cipher_suites
    vector(&mut body, 1)?; // legacy_compression_methods
    let mut extensions = vector(&mut body, 2)?;
    let mut params = None;
    while !extensions.is_empty() {
        let ty = uint(&mut extensions, 2)?;
        let data = vector(&mut extensions, 2)?;
        match ty {
            // early_data
            0x2a => return None,
            // quic_transport_parameters of QUIC versions 1 and 2
            0x39 => params = Some(data),
            _ => {}
        }
    }

    let mut params = params?;
    while !params.is_empty() {
        let id = BufExt::get_var(&mut params).ok()?;
        let len = usize::try_from(BufExt::get_var(&mut params).ok()?).ok()?;
        let value = take(&mut params, len)?;
        if id == VERSION_INFORMATION_ID {
            return Some(VersionInformationParameter::read(Side::Server, value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_information(side: Side, versions: &[u32]) -> VersionInformationParameter {
        let value = versions
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<_>>();
        VersionInformationParameter::read(side, &value)
    }

    fn client_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut exts = Vec::new();
        for (ty, data) in extensions {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hello = vec![1];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    #[test]
    fn version_information_in_client_hello() {
        // initial_max_data = 0x40, then version_information: chosen 1, available 2, 1
        let params = hex_literal::hex!(
            "04 02 4040
             11 0c 00000001 6b3343cf 00000001"
        );
        let hello = client_hello(&[(0x0a, &[0, 2, 0, 0x1d]), (0x39, &params)]);
        let offer = client_hello_version_information(&hello).unwrap();
        assert!(offer.is_valid());
        assert_eq!(offer.chosen(), 1);
        assert!(offer.lists(QUIC_VERSION_2));

        // Incomplete
        assert!(client_hello_version_information(&hello[..hello.len() - 1]).is_none());
        // Attempts 0-RTT
        let hello = client_hello(&[(0x39, &params), (0x2a, &[])]);
        assert!(client_hello_version_information(&hello).is_none());
        // No version_information
        let hello = client_hello(&[(0x39, &params[..4])]);
        assert!(client_hello_version_information(&hello).is_none());
    }

    #[test]
    fn server_preference() {
        let params = hex_literal::hex!("11 0c 00000001 6b3343cf 00000001");
        let hello = client_hello(&[(0x39, &params)]);
        let mut payload = Vec::new();
        frame::Crypto {
            offset: 0,
            data: hello.into(),
        }
        .encode(&mut payload);
        for (supported, expected) in [
            (&[QUIC_VERSION_2, 1][..], QUIC_VERSION_2),
            (&[1, QUIC_VERSION_2][..], 1),
            (&[1][..], 1),
        ] {
            assert_eq!(negotiate_version(1, &payload, supported), expected);
        }
        // Draft versions have no compatible version
        assert_eq!(
            negotiate_version(0xff00_001d, &payload, &[QUIC_VERSION_2, 0xff00_001d]),
            0xff00_001d
        );
    }

    #[test]
    fn check_received_version_information() {
        use Side::*;
        let v2 = QUIC_VERSION_2;
        let offer = version_information(Server, &[1, v2, 1]);
        let check = |side, original, negotiated, received: &[u32]| {
            let received = version_information(side, received);
            check_version_information(side, &offer, original, negotiated, Some(&received))
                .map_err(|e| e.code)
        };
        let vn_error = Err(TransportErrorCode::VERSION_NEGOTIATION_ERROR);
        let tp_error = Err(TransportErrorCode::TRANSPORT_PARAMETER_ERROR);

        // The server switched to version 2
        assert_eq!(check(Client, 1, v2, &[v2, 1, v2]), Ok(()));
        // It claims another version than the one it switched to
        assert_eq!(check(Client, 1, v2, &[1, 1, v2]), vn_error);
        // It chose a version the client did not offer
        assert_eq!(check(Client, 1, 0x0a0a_0a0a, &[0x0a0a_0a0a]), vn_error);
        // Malformed
        assert_eq!(check(Client, 1, 1, &[0]), tp_error);
        assert_eq!(check(Client, 1, 1, &[1, 0]), tp_error);
        assert_eq!(check(Client, 1, 1, &[]), tp_error);

        // The client's first flight was version 1
        assert_eq!(check(Server, 1, v2, &[1, v2, 1]), Ok(()));
        assert_eq!(check(Server, 1, 1, &[v2, v2, 1]), vn_error);
        // The chosen version is missing from the client's available versions
        assert_eq!(check(Server, 1, 1, &[1, v2]), tp_error);

        // Absent
        assert_eq!(
            check_version_information(Client, &offer, 1, v2, None),
            Ok(())
        );
    }
}
