//! Settings that shape the observable wire image of a connection
//!
//! Upstream Quinn picks sensible values for everything that is visible on the wire but not
//! negotiated: the layout of the transport parameters, how packet numbers are chosen, how the
//! ClientHello is spread over Initial packets, how datagrams are padded, and so on. Other QUIC
//! stacks make different choices, which allows observers to tell implementations apart. The types
//! in this module let an embedder describe those choices explicitly, e.g. to make a client
//! indistinguishable from a particular browser. Every default reproduces upstream behaviour.
//!
//! The options model the behaviour of QUICHE (Chromium), neqo (Firefox) and Apple's stack
//! (Safari), as seen in packet
//! captures and described in their sources. The implementation is Quinn's own, except for the
//! parts that name the code they are translated from; THIRD-PARTY-NOTICES lists those.

use std::{fmt, sync::Arc};

use bytes::Bytes;
use rand::RngCore;

use crate::{ConfigError, Duration, MIN_INITIAL_SIZE, VarInt};

/// Maximum number of parameters accepted by [`TransportParameterLayout::extra_parameter`]
pub const MAX_EXTRA_TRANSPORT_PARAMETERS: usize = 4;

/// Maximum value length accepted by [`TransportParameterLayout::extra_parameter`]
pub const MAX_EXTRA_TRANSPORT_PARAMETER_LEN: usize = 32;

/// Maximum number of versions in a [`VersionInformation`], including a GREASE version
pub const MAX_AVAILABLE_VERSIONS: usize = 8;

/// Codepoint of `min_ack_delay` in draft-ietf-quic-ack-frequency-07 and later, as sent upstream
pub(crate) const MIN_ACK_DELAY_DRAFT07: u64 = 0xff04_de1b;

/// Codepoint of `version_information` (RFC 9368)
pub(crate) const VERSION_INFORMATION_ID: u64 = 0x11;

/// Whether Quinn writes the transport parameter `id` itself, so that it cannot be supplied as an
/// additional raw parameter
fn is_reserved(id: VarInt) -> bool {
    // The RFC 9000 parameters, version_information, max_datagram_frame_size and grease_quic_bit
    matches!(
        id.into_inner(),
        0x00..=VERSION_INFORMATION_ID | 0x20 | 0x2ab2
    )
}

/// Which optional transport parameters this endpoint sends, and in which order
///
/// The values of the individual parameters come from [`TransportConfig`] and [`EndpointConfig`];
/// this type decides which optional and extension parameters are present and how the resulting
/// list is ordered on the wire.
///
/// The default reproduces upstream Quinn: a fresh random order for every connection, one reserved
/// ("GREASE") parameter, `min_ack_delay` under the draft-07 codepoint `0xff04de1b`, no
/// `version_information` and no additional parameters.
///
/// [`TransportConfig`]: crate::TransportConfig
/// [`EndpointConfig`]: crate::EndpointConfig
#[derive(Clone, Debug)]
pub struct TransportParameterLayout {
    pub(crate) order: TransportParameterOrder,
    pub(crate) grease: bool,
    pub(crate) min_ack_delay_id: Option<VarInt>,
    pub(crate) version_information: Option<VersionInformation>,
    pub(crate) extra: Vec<(VarInt, Bytes)>,
    pub(crate) connection_id_limit_with_empty_cid: bool,
}

impl TransportParameterLayout {
    /// Order in which the parameters appear on the wire
    ///
    /// Defaults to [`TransportParameterOrder::Random`].
    pub fn order(&mut self, order: TransportParameterOrder) -> &mut Self {
        self.order = order;
        self
    }

    /// Send `active_connection_id_limit` also when this endpoint's own connection IDs are empty
    ///
    /// Upstream Quinn leaves the parameter out then. Apple's stack (Safari) sends it with its
    /// empty source connection ID. Disabled by default.
    pub fn connection_id_limit_with_empty_cid(&mut self, enabled: bool) -> &mut Self {
        self.connection_id_limit_with_empty_cid = enabled;
        self
    }

    /// Whether to send one reserved transport parameter (RFC 9000, section 18.1)
    ///
    /// The parameter gets a random identifier of the form `31 * N + 27` and a random value of 0 to
    /// 15 bytes, freshly chosen for every connection. This is the same scheme quiche uses. Enabled
    /// by default.
    pub fn grease(&mut self, enabled: bool) -> &mut Self {
        self.grease = enabled;
        self
    }

    /// Codepoint under which the `min_ack_delay` parameter of the ACK frequency extension is sent,
    /// or `None` to omit the parameter
    ///
    /// Advertising `min_ack_delay` tells the peer that this endpoint accepts `ACK_FREQUENCY` and
    /// `IMMEDIATE_ACK` frames; the value is always 1000 microseconds. Defaults to `0xff04de1b`,
    /// the codepoint of draft-ietf-quic-ack-frequency-07 and later.
    ///
    /// Older drafts used other codepoints, e.g. `0xff02de1a` for draft-02, which Firefox
    /// advertises. Their `ACK_FREQUENCY` frame has the same wire layout but other semantics,
    /// which Quinn does not implement: draft-02's "packet tolerance", the number of ack-eliciting
    /// packets after which an acknowledgement is sent, is one more than the "ack-eliciting
    /// threshold" Quinn reads from that field, and its last field is an "ignore order" flag
    /// (1: do not acknowledge reordered packets at once) that Quinn reads as a reordering
    /// threshold of 1 (acknowledge them at once). Quinn therefore follows a draft-02 peer's frame
    /// with one packet more between acknowledgements than asked and with the opposite reordering
    /// behaviour; a draft-02 peer misreads Quinn's own `ACK_FREQUENCY` frames, which are only
    /// sent when configured, the same way. draft-02 defines `IMMEDIATE_ACK` as `0xac`, which Quinn
    /// does not understand: receiving it closes the connection.
    ///
    /// Fails if the codepoint belongs to a parameter Quinn writes itself or to a parameter added
    /// with [`extra_parameter`](Self::extra_parameter).
    pub fn min_ack_delay(&mut self, codepoint: Option<VarInt>) -> Result<&mut Self, ConfigError> {
        if let Some(id) = codepoint {
            if is_reserved(id) || self.extra.iter().any(|(x, _)| *x == id) {
                return Err(ConfigError::OutOfBounds);
            }
        }
        self.min_ack_delay_id = codepoint;
        Ok(self)
    }

    /// Send the `version_information` parameter (RFC 9368) with the given content
    ///
    /// Compatible version negotiation: if a client lists the version compatible with its own
    /// (QUIC versions 1 and 2, RFC 9369), a server may switch the connection to it, and the client
    /// follows if its crypto session supports
    /// [`Session::set_version`](crate::crypto::Session::set_version). Sessions of the rustls
    /// provider do not; their handshake then fails with `VERSION_NEGOTIATION_ERROR`. A client
    /// must list its own version, and only versions in
    /// [`EndpointConfig::supported_versions`](crate::EndpointConfig::supported_versions), or
    /// connecting fails with [`ConnectError::UnsupportedVersion`](crate::ConnectError). An
    /// endpoint that sends the parameter validates the peer's (RFC 9368, section 4).
    ///
    /// `None`, the default, omits it unless QUIC version 2 is in use, which requires the
    /// parameter: a client of version 2 then lists only version 2, a server that supports
    /// version 2 its supported versions. Fails if the version list, including a GREASE version,
    /// has more than [`MAX_AVAILABLE_VERSIONS`] entries.
    pub fn version_information(
        &mut self,
        value: Option<VersionInformation>,
    ) -> Result<&mut Self, ConfigError> {
        if let Some(info) = &value {
            let grease = !matches!(info.grease, GreaseVersion::None);
            if info.available.len() + usize::from(grease) > MAX_AVAILABLE_VERSIONS {
                return Err(ConfigError::OutOfBounds);
            }
            if let GreaseVersion::At(index) = info.grease {
                if index > info.available.len() {
                    return Err(ConfigError::OutOfBounds);
                }
            }
        }
        self.version_information = value;
        Ok(self)
    }

    /// Append a transport parameter that Quinn does not know, with a verbatim value
    ///
    /// Useful for implementation-specific parameters such as quiche's `google_connection_options`
    /// (`0x3128`, a list of four-byte tags) or for advertising extensions by their codepoint. The
    /// parameter is only sent; Quinn does not act on it, so advertising an extension that makes
    /// the peer send frames Quinn does not implement lets such a peer break the connection. The
    /// one exception is `reset_stream_at` (`0x1d`), which Firefox advertises: Quinn accepts its
    /// `RESET_STREAM_AT` frames and treats them like `RESET_STREAM`, without delivering the
    /// reliable part of the stream.
    ///
    /// Fails if more than [`MAX_EXTRA_TRANSPORT_PARAMETERS`] parameters are added, if the value is
    /// longer than [`MAX_EXTRA_TRANSPORT_PARAMETER_LEN`] bytes, or if the identifier is already in
    /// use: by another extra parameter, by the configured `min_ack_delay` codepoint, or by a
    /// parameter Quinn writes itself (the RFC 9000 parameters, `version_information`,
    /// `max_datagram_frame_size` and `grease_quic_bit`).
    pub fn extra_parameter(
        &mut self,
        id: VarInt,
        value: impl Into<Bytes>,
    ) -> Result<&mut Self, ConfigError> {
        let value = value.into();
        if self.extra.len() >= MAX_EXTRA_TRANSPORT_PARAMETERS
            || value.len() > MAX_EXTRA_TRANSPORT_PARAMETER_LEN
            || is_reserved(id)
            || self.min_ack_delay_id == Some(id)
            || self.extra.iter().any(|(x, _)| *x == id)
        {
            return Err(ConfigError::OutOfBounds);
        }
        self.extra.push((id, value));
        Ok(self)
    }
}

impl Default for TransportParameterLayout {
    fn default() -> Self {
        Self {
            order: TransportParameterOrder::Random,
            grease: true,
            // MIN_ACK_DELAY_DRAFT07 fits VarInt's 62-bit range.
            min_ack_delay_id: Some(VarInt::from_u64(MIN_ACK_DELAY_DRAFT07).unwrap()),
            version_information: None,
            extra: Vec::new(),
            connection_id_limit_with_empty_cid: false,
        }
    }
}

/// Order of the transport parameters on the wire
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransportParameterOrder {
    /// A fresh uniformly random permutation for every connection (upstream Quinn, quiche)
    #[default]
    Random,
    /// The listed identifiers first, in the given order
    ///
    /// Identifiers of parameters that are not sent are skipped. Parameters that are sent but not
    /// listed, including the reserved GREASE parameter whose identifier is random, follow in
    /// ascending order of their identifiers.
    Fixed(Vec<VarInt>),
    /// The listed identifiers in the given cyclic order, starting at a random one of those that
    /// are sent, as Apple's stack (Safari) writes its parameters
    ///
    /// Parameters that are sent but not listed follow in ascending order of their identifiers.
    Rotated(Vec<VarInt>),
}

/// Content of the `version_information` transport parameter (RFC 9368)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInformation {
    pub(crate) available: Vec<u32>,
    pub(crate) grease: GreaseVersion,
}

impl VersionInformation {
    /// Advertise `available` as the list of available versions, in this order
    ///
    /// The chosen version is the version of the connection. No GREASE version is added.
    pub fn new(available: Vec<u32>) -> Self {
        Self {
            available,
            grease: GreaseVersion::None,
        }
    }

    /// Where to insert a reserved version of the form `0x?a?a?a?a` into the available versions
    ///
    /// The reserved version is drawn afresh for every connection.
    pub fn grease(&mut self, grease: GreaseVersion) -> &mut Self {
        self.grease = grease;
        self
    }
}

/// Placement of a reserved ("GREASE") version in [`VersionInformation`]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GreaseVersion {
    /// No reserved version
    #[default]
    None,
    /// Insert the reserved version at this index of the available versions (0 = first)
    At(usize),
    /// Insert the reserved version at a uniformly random index for every connection, as quiche
    /// does
    Random,
}

/// Wire behaviour that is not negotiated but visible to the peer or to on-path observers
///
/// Set through [`TransportConfig::fingerprint`](crate::TransportConfig::fingerprint). The default
/// reproduces upstream Quinn. Options marked as client-only have no effect on server
/// connections.
#[derive(Clone, Debug)]
pub struct FingerprintConfig {
    pub(crate) packet_numbering: PacketNumbering,
    pub(crate) initial_padding: InitialPadding,
    pub(crate) crypto_framing: CryptoFraming,
    pub(crate) coalesce_packets: bool,
    pub(crate) spin_bit: SpinBit,
    pub(crate) grease_fixed_bit: bool,
    pub(crate) early_key_update: bool,
    pub(crate) ack_decimation: Option<AckDecimation>,
    pub(crate) ack_policy: AckPolicy,
    pub(crate) ack_each_datagram: bool,
    pub(crate) early_connection_ids: bool,
    pub(crate) packet_padding: PacketPadding,
    pub(crate) trailing_ping: bool,
    pub(crate) buffered_packet_processing: BufferedPacketProcessing,
    pub(crate) finished_with_first_data: bool,
}

impl FingerprintConfig {
    /// How packet numbers are chosen and encoded
    ///
    /// Defaults to [`PacketNumbering::Standard`].
    pub fn packet_numbering(&mut self, mut value: PacketNumbering) -> &mut Self {
        if let PacketNumbering::Shared { first } = &mut value {
            *first = (*first).min(MAX_FIRST_PACKET_NUMBER);
        }
        self.packet_numbering = value;
        self
    }

    /// How a client pads datagrams that carry Initial packets (client-only)
    ///
    /// Defaults to [`InitialPadding::Standard`]. [`CryptoFraming::ChaosProtection`] and
    /// [`CryptoFraming::SniSlicing`] only occur with one padding style each, which they then
    /// impose, see [`crypto_framing`](Self::crypto_framing).
    pub fn initial_padding(&mut self, value: InitialPadding) -> &mut Self {
        self.initial_padding = value;
        self
    }

    /// How a client frames CRYPTO data in Initial packets (client-only)
    ///
    /// Defaults to [`CryptoFraming::InOrder`]. The browser framings imply the padding style of
    /// the browser: [`ChaosProtection`](CryptoFraming::ChaosProtection) pads with PADDING frames
    /// ([`InitialPadding::Frames`]), [`SniSlicing`](CryptoFraming::SniSlicing) with trailing
    /// zeros ([`InitialPadding::TrailingZeros`]). The size comes from
    /// [`initial_padding`](Self::initial_padding), or is 1200 bytes if that is
    /// [`InitialPadding::Standard`].
    pub fn crypto_framing(&mut self, value: CryptoFraming) -> &mut Self {
        self.crypto_framing = value;
        self
    }

    /// Whether packets of different packet number spaces may share a UDP datagram
    ///
    /// When disabled, every QUIC packet is sent in a datagram of its own. Coalescing saves
    /// datagrams during the handshake; browsers coalesce what they send at the same moment, e.g.
    /// the reply to the server's flight of a resumed handshake. Enabled by default.
    pub fn coalesce_packets(&mut self, enabled: bool) -> &mut Self {
        self.coalesce_packets = enabled;
        self
    }

    /// Value of the latency spin bit in short header packets
    ///
    /// Defaults to [`SpinBit::Standard`].
    pub fn spin_bit(&mut self, value: SpinBit) -> &mut Self {
        self.spin_bit = value;
        self
    }

    /// Whether to randomise the fixed bit of outgoing packets when the peer advertised
    /// `grease_quic_bit` (RFC 9287)
    ///
    /// Each packet then has the bit cleared with probability one half. Enabled by default.
    pub fn grease_fixed_bit(&mut self, enabled: bool) -> &mut Self {
        self.grease_fixed_bit = enabled;
        self
    }

    /// Whether to update the 1-RTT keys early in the connection
    ///
    /// Upstream Quinn performs its first key update after a random number of 10 to 999 packets so
    /// that peers with broken key update support fail early. When disabled, keys are only updated
    /// when the peer initiates an update or when the confidentiality limit of the cipher
    /// approaches. Enabled by default.
    pub fn early_key_update(&mut self, enabled: bool) -> &mut Self {
        self.early_key_update = enabled;
        self
    }

    /// Acknowledge less often once the connection has received a number of packets
    ///
    /// `None`, the default, keeps acknowledging every second ack-eliciting packet or after the
    /// local `max_ack_delay`. The decimation is suspended while the peer controls the
    /// acknowledgement rate through `ACK_FREQUENCY` frames.
    pub fn ack_decimation(&mut self, value: Option<AckDecimation>) -> &mut Self {
        self.ack_decimation = value;
        self
    }

    /// When acknowledgements become due and which packets carry them
    ///
    /// Defaults to [`AckPolicy::Standard`].
    pub fn ack_policy(&mut self, value: AckPolicy) -> &mut Self {
        self.ack_policy = value;
        self
    }

    /// Whether acknowledgements are sent as if every received datagram were answered before the
    /// next one is processed
    ///
    /// Browsers process one datagram at a time and send what became due right after it, so a
    /// burst of three ack-eliciting server Initial packets yields three ACK-only Initial packets
    /// from neqo. An endpoint that is handed several datagrams at once processes all of them
    /// before it transmits, which merges these acknowledgements into one. When enabled, an ACK
    /// frame that is due when the next datagram arrives is kept with the packets it acknowledged
    /// at that moment and sent in a packet of its own, ahead of the ACK frames of later
    /// datagrams. That packet carries other frames only if some were ready at that moment.
    /// Coalesced packets share its datagram if they carry ACK frames kept at the same moment or
    /// other frames, which may have been ready then, but not if they only acknowledge later
    /// datagrams. The packets on the wire match datagram-by-datagram processing; only their
    /// timing differs. Disabled by default.
    pub fn ack_each_datagram(&mut self, enabled: bool) -> &mut Self {
        self.ack_each_datagram = enabled;
        self
    }

    /// Whether a client requests a connection ID to issue as soon as the connection is created
    /// (client-only)
    ///
    /// Upstream Quinn asks the endpoint for connection IDs once the handshake is complete, so its
    /// NEW_CONNECTION_ID frames trail the first 1-RTT packets. neqo issues one immediately and
    /// sends it in its first 0-RTT or 1-RTT packet, before any STREAM frame. When enabled, the
    /// endpoint issues one connection ID while it creates the connection (every peer accepts at
    /// least two, the one used during the handshake included); the remainder up to the peer's
    /// `active_connection_id_limit` follows when the handshake completes. The early frame does not
    /// cause a 0-RTT packet by itself: it waits for the first 0-RTT packet with application data,
    /// or else for the first 1-RTT packet. Has no effect with zero-length local connection IDs.
    /// Disabled by default.
    pub fn early_connection_ids(&mut self, enabled: bool) -> &mut Self {
        self.early_connection_ids = enabled;
        self
    }

    /// How packets other than Initial packets are padded to their minimum size
    ///
    /// Defaults to [`PacketPadding::Standard`].
    pub fn packet_padding(&mut self, value: PacketPadding) -> &mut Self {
        self.packet_padding = value;
        self
    }

    /// Whether a PING frame is written after the other frames of its packet instead of before
    /// the ACK frame
    ///
    /// quiche and neqo both append a PING, e.g. `ACK PING`; upstream Quinn writes `PING ACK`.
    /// Disabled by default.
    pub fn trailing_ping(&mut self, enabled: bool) -> &mut Self {
        self.trailing_ping = enabled;
        self
    }

    /// When 1-RTT packets are processed that arrived while the handshake waited for
    /// asynchronous work (see [`crypto::Session::poll_handshake`](crate::crypto::Session))
    ///
    /// Defaults to [`BufferedPacketProcessing::Immediate`].
    pub fn buffered_packet_processing(&mut self, value: BufferedPacketProcessing) -> &mut Self {
        self.buffered_packet_processing = value;
        self
    }

    /// Whether a client that completes the handshake while it processes a packet sends its
    /// Finished together with the application's first stream data
    ///
    /// Matches quiche, which writes the HTTP/3 control stream as soon as 1-RTT keys exist, still
    /// within the flush of the packet that completed the handshake. When enabled, the connection
    /// instead waits briefly for the application to queue stream data: it sends nothing until
    /// then, until a pending acknowledgement reaches its deadline
    /// ([`Connection::ack_deadline`]), or for 2 ms, whichever comes first, or up to 0.5 ms if
    /// the acknowledgement deadline had already passed when the handshake completed.
    ///
    /// The Finished goes out at once instead after a handshake that completes asynchronously (see
    /// [`crypto::Session::poll_handshake`](crate::crypto::Session::poll_handshake)) or with 0-RTT,
    /// whose control stream already went out in 0-RTT packets. Client-only. Disabled by default.
    ///
    /// [`Connection::ack_deadline`]: crate::Connection::ack_deadline
    pub fn finished_with_first_data(&mut self, enabled: bool) -> &mut Self {
        self.finished_with_first_data = enabled;
        self
    }
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            packet_numbering: PacketNumbering::Standard,
            initial_padding: InitialPadding::Standard,
            crypto_framing: CryptoFraming::InOrder,
            coalesce_packets: true,
            spin_bit: SpinBit::Standard,
            grease_fixed_bit: true,
            early_key_update: true,
            ack_decimation: None,
            ack_policy: AckPolicy::Standard,
            ack_each_datagram: false,
            early_connection_ids: false,
            packet_padding: PacketPadding::Standard,
            trailing_ping: false,
            buffered_packet_processing: BufferedPacketProcessing::Immediate,
            finished_with_first_data: false,
        }
    }
}

/// When acknowledgements become due and which packets carry them
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AckPolicy {
    /// Upstream Quinn
    ///
    /// Initial and Handshake packets are acknowledged immediately. In the application data space
    /// every second ack-eliciting packet is acknowledged immediately, as is any packet that
    /// arrives out of order, which includes a first packet whose number is not 0 or 1;
    /// otherwise after the local `max_ack_delay`. ACK frames are only sent once they are due.
    #[default]
    Standard,
    /// quiche (Chrome), as a client
    ///
    /// In every packet number space, an ACK is due after the second ack-eliciting packet since
    /// the last one, when a packet opens a gap in received packet numbers (and for the four
    /// packets after the gap), or when a missing packet older than the largest acknowledged one
    /// arrives; otherwise 1 ms after the first unacknowledged ack-eliciting packet in the Initial
    /// and Handshake spaces, and after the local `max_ack_delay` in the application data space.
    /// Numbers skipped before a space's first packet are not a gap, so the server's first 1-RTT
    /// packet is not acknowledged at once.
    ///
    /// A pending acknowledgement rides along in every ack-eliciting packet of its space, even
    /// before it is due. Since the Initial keys are discarded with the first Handshake packet, an
    /// Initial acknowledgement not yet due when the client's Finished is sent is never sent, as
    /// with quiche on resumption. After 19 packets in a row carried no ack-eliciting frame, the
    /// next ACK-only 1-RTT packet also carries a MAX_DATA frame repeating the connection's
    /// receive limit, so the peer acknowledges it. A quiche server's held-back first Initial
    /// acknowledgement is not reproduced.
    Quiche,
}

/// When a client processes 1-RTT packets that arrived while its handshake waited for
/// asynchronous work, e.g. the verification of the server's certificate
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BufferedPacketProcessing {
    /// As soon as the handshake completes, before the client sends anything
    ///
    /// The client's first packets then acknowledge them, e.g. the server's first 1-RTT packet in
    /// the packet with the HTTP/3 control stream.
    #[default]
    Immediate,
    /// After the client has sent its Finished and its first ack-eliciting 1-RTT packet, as quiche
    /// (Chrome) does
    ///
    /// quiche installs the 1-RTT keys when its asynchronous certificate verification completes,
    /// sends the Finished and, through the HTTP/3 session, the SETTINGS on the control stream,
    /// and only then processes the kept packets from an alarm
    /// (`QuicConnection::SetDecrypter`, `MaybeProcessUndecryptablePackets`). The control stream
    /// thus goes out alone and the acknowledgement of the server's first 1-RTT packet follows
    /// with the request. The packets are processed at the latest 5 ms after the handshake
    /// completed, or before the next datagram from the peer.
    AfterFirst1rttData,
}

/// How packets other than Initial packets are padded to their minimum size
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketPadding {
    /// Upstream Quinn
    ///
    /// PADDING frames after the other frames, until the packet is large enough for header
    /// protection sampling and at least 22 bytes longer than the destination connection ID, e.g.
    /// 30 bytes for a lone PING with an 8-byte destination connection ID.
    #[default]
    Standard,
    /// quiche (Chrome)
    ///
    /// PADDING frames in front of the other frames, only as many as header protection needs:
    /// packet number and payload together take at least 4 bytes, e.g. `PADDING(2) PING` in a
    /// 29-byte packet with an 8-byte destination connection ID and a one-byte packet number.
    /// Packets remain at least 22 bytes longer than the local connection ID, which is what RFC
    /// 9000, section 10.3 asks for so that the peer can answer any packet with a stateless reset
    /// that is smaller than it and still looks like a valid packet.
    Leading,
}

/// How packet numbers are chosen and how long their encoding is
#[derive(Clone, Debug, Default)]
pub enum PacketNumbering {
    /// Upstream Quinn
    ///
    /// Every packet number space counts from 0. The application data space occasionally skips a
    /// number to detect optimistic ACKs. The encoded length covers twice the distance to the
    /// largest acknowledged packet, taking 0 if none has been acknowledged (RFC 9000, section
    /// 17.1).
    #[default]
    Standard,
    /// Separate counters without skipped numbers, as neqo (Firefox) uses them
    ///
    /// The Handshake and application data spaces count from 0; the Initial space starts at
    /// `first_initial`. The encoded length covers twice the distance to the largest acknowledged
    /// packet, or `packet number + 1` while nothing has been acknowledged in the space.
    Sequential {
        /// First packet number of the Initial space
        first_initial: FirstPacketNumber,
    },
    /// A single counter shared by all packet number spaces, starting at `first`, as quiche
    /// (Chrome) uses it
    ///
    /// With `first = 1`, a client sends e.g. Initial packets 1 to 3, Handshake packets 4 and 5 and
    /// 1-RTT packets from 6 on. Like quiche, one number is skipped whenever a probe timeout
    /// fires, to elicit an immediate acknowledgement; no other numbers are skipped. Encoded
    /// lengths follow RFC 9000 as for [`Standard`](Self::Standard).
    Shared {
        /// Packet number of the first packet of the connection
        ///
        /// [`FingerprintConfig::packet_numbering`] reduces values above
        /// [`MAX_FIRST_PACKET_NUMBER`] to it.
        first: u64,
    },
}

/// First packet number of a packet number space
///
/// Values above [`MAX_FIRST_PACKET_NUMBER`] are reduced to it, so that the packet numbers of a
/// connection neither run out nor need more than the four bytes a packet number can be encoded in.
#[derive(Clone)]
pub enum FirstPacketNumber {
    /// Always the same value
    Fixed(u64),
    /// Drawn for every connection by the given function from the connection's random number
    /// generator
    ///
    /// neqo, for example, draws `1 + (r0 & 0x1f) + (r1.saturating_sub(224) << 5)` from two random
    /// bytes `r0` and `r1`, i.e. a value from 1 to 1024 that is below 33 seven times out of
    /// eight.
    #[allow(clippy::type_complexity)]
    Random(Arc<dyn Fn(&mut dyn RngCore) -> u64 + Send + Sync>),
}

impl FirstPacketNumber {
    pub(crate) fn draw(&self, rng: &mut dyn RngCore) -> u64 {
        let value = match self {
            Self::Fixed(x) => *x,
            Self::Random(f) => f(rng),
        };
        value.min(MAX_FIRST_PACKET_NUMBER)
    }
}

/// Largest first packet number used by [`PacketNumbering`]; larger values are reduced to it
pub const MAX_FIRST_PACKET_NUMBER: u64 = (1 << 30) - 1;

impl fmt::Debug for FirstPacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(x) => f.debug_tuple("Fixed").field(x).finish(),
            Self::Random(_) => f.write_str("Random(..)"),
        }
    }
}

/// How a client pads UDP datagrams that carry Initial packets
///
/// RFC 9000 requires such datagrams to be at least 1200 bytes long.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InitialPadding {
    /// Upstream Quinn
    ///
    /// PADDING frames at the end of the datagram's last packet up to 1200 bytes. Datagrams may be
    /// larger, up to the current MTU, when the ClientHello fills them.
    #[default]
    Standard,
    /// Every datagram that carries an Initial packet is exactly `size` bytes long, padded with
    /// PADDING frames at the end of the Initial packet, as quiche does
    ///
    /// If other packets follow the Initial packet in the datagram, the Initial packet is padded
    /// so that the whole datagram has `size` bytes, as quiche's coalescer does.
    ///
    /// While Initial keys are in use no datagram exceeds `size`, so the first flight never
    /// exceeds it either. `size` must be at least 1200 and should not exceed the path MTU.
    Frames {
        /// Datagram size in bytes
        size: u16,
    },
    /// Every datagram that carries an Initial packet is exactly `size` bytes long, as neqo does
    ///
    /// If the datagram's last packet is an ack-eliciting 1-RTT packet it is padded with PADDING
    /// frames; otherwise zero bytes are appended after the last packet, outside of any packet.
    /// Receivers discard such trailing bytes. While Initial keys are in use no datagram exceeds
    /// `size`. `size` must be at least 1200 and should not exceed the path MTU.
    TrailingZeros {
        /// Datagram size in bytes
        size: u16,
    },
}

impl FingerprintConfig {
    /// The padding of datagrams carrying Initial packets, with the style the CRYPTO framing
    /// implies
    pub(crate) fn effective_initial_padding(&self) -> InitialPadding {
        let size = self
            .initial_padding
            .fixed_size()
            .unwrap_or(MIN_INITIAL_SIZE);
        match self.crypto_framing {
            CryptoFraming::InOrder | CryptoFraming::Chunked { .. } => self.initial_padding,
            CryptoFraming::ChaosProtection => InitialPadding::Frames { size },
            CryptoFraming::SniSlicing => InitialPadding::TrailingZeros { size },
        }
    }
}

impl InitialPadding {
    /// Exact size of datagrams carrying Initial packets, if fixed
    pub(crate) fn fixed_size(self) -> Option<u16> {
        match self {
            Self::Standard => None,
            Self::Frames { size } | Self::TrailingZeros { size } => {
                Some(size.max(MIN_INITIAL_SIZE))
            }
        }
    }
}

/// How a client frames CRYPTO data in Initial packets
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CryptoFraming {
    /// Upstream Quinn: CRYPTO data in order, each packet filled before the next one is started
    #[default]
    InOrder,
    /// quiche's "chaos protection"
    ///
    /// A ClientHello that needs more than one packet is split so that the first packet carries
    /// its first 55 to 86 bytes and its end, with all packets filled roughly equally; the rest
    /// follows in order. Every Initial packet that carries CRYPTO data and has room left is
    /// padded to the full datagram size, and that room is used to split the CRYPTO data into
    /// 2 to 10 additional frames, to add 2 to 10 PING frames and to spread PADDING frames
    /// between them, after which all frames except ACK are shuffled. Use together with
    /// [`InitialPadding::Frames`] and [`PacketNumbering::Shared`], like quiche; the Initial
    /// packet following the first ClientHello packet then gets a two-byte packet number, as it
    /// does in quiche.
    ChaosProtection,
    /// neqo's "SNI slicing"
    ///
    /// When the CRYPTO data at offset 0 contains a ClientHello with a server name, it is cut in
    /// the middle of the server name. The first packet carries the part after the cut and then
    /// the part before it, both shortened so that the ClientHello is spread over roughly equally
    /// filled packets; that packet ends its datagram. The remaining data follows in order. Use
    /// together with [`InitialPadding::TrailingZeros`], like neqo.
    SniSlicing,
    /// Apple's stack (Safari): CRYPTO data in order, at most `max` bytes in each Initial packet,
    /// which ends its datagram
    ///
    /// Safari puts 999 bytes of its ClientHello into the first packet and the rest into the
    /// second. Use together with [`InitialPadding::Frames`], like Safari.
    Chunked {
        /// Most CRYPTO data per packet
        max: u16,
    },
}

/// Value of the latency spin bit (RFC 9000, section 17.4)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpinBit {
    /// Upstream Quinn: if [`TransportConfig::allow_spin`](crate::TransportConfig::allow_spin)
    /// is set, spin on seven out of eight connections; otherwise, and on the remaining
    /// connections, send a random value on every packet
    #[default]
    Standard,
    /// Never set the bit, as quiche does
    Zero,
    /// A random value on every packet, as neqo does
    Random,
}

/// Parameters for acknowledging less often once a connection is established
///
/// Mirrors quiche's receiver-side ACK decimation. The default values are quiche's.
#[derive(Clone, Debug, PartialEq)]
pub struct AckDecimation {
    pub(crate) after_packets: u64,
    pub(crate) packets_per_ack: u64,
    pub(crate) rtt_fraction: f32,
}

impl AckDecimation {
    /// Start decimating once the peer's 1-RTT packet numbers have advanced this far beyond the
    /// first one received
    ///
    /// Defaults to 100.
    pub fn after_packets(&mut self, value: u64) -> &mut Self {
        self.after_packets = value;
        self
    }

    /// Acknowledge immediately after this many ack-eliciting packets
    ///
    /// Defaults to 10. Values below 1 are treated as 1.
    pub fn packets_per_ack(&mut self, value: u64) -> &mut Self {
        self.packets_per_ack = value;
        self
    }

    /// Otherwise acknowledge after this fraction of the minimum RTT, capped by the local
    /// `max_ack_delay` and at least 1 ms
    ///
    /// Defaults to 0.25. Negative values and NaN count as 0, infinity as `max_ack_delay`.
    pub fn rtt_fraction(&mut self, value: f32) -> &mut Self {
        self.rtt_fraction = match value.is_nan() {
            true => 0.0,
            false => value.max(0.0),
        };
        self
    }

    pub(crate) fn delay(&self, min_rtt: Duration, max_ack_delay: Duration) -> Duration {
        let delay = min_rtt.as_secs_f64() * f64::from(self.rtt_fraction);
        let delay = match delay < max_ack_delay.as_secs_f64() {
            true => Duration::from_secs_f64(delay),
            false => max_ack_delay,
        };
        delay.max(crate::TIMER_GRANULARITY)
    }
}

impl Default for AckDecimation {
    fn default() -> Self {
        Self {
            after_packets: 100,
            packets_per_ack: 10,
            rtt_fraction: 0.25,
        }
    }
}
