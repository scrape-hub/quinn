//! QUIC connection transport parameters
//!
//! The `TransportParameters` type is used to represent the transport parameters
//! negotiated by peers while establishing a QUIC connection. This process
//! happens as part of the establishment of the TLS session. As such, the types
//! contained in this modules should generally only be referred to by custom
//! implementations of the `crypto::Session` trait.

use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use bytes::{Buf, BufMut};
use rand::{Rng as _, RngCore, seq::SliceRandom as _};
use thiserror::Error;

use crate::{
    LOC_CID_COUNT, MAX_CID_SIZE, MAX_STREAM_COUNT, QUIC_VERSION_2, RESET_TOKEN_SIZE, ResetToken,
    Side, TIMER_GRANULARITY, TransportError, VarInt,
    cid_generator::ConnectionIdGenerator,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    config::{
        EndpointConfig, GreaseVersion, MAX_AVAILABLE_VERSIONS, MAX_EXTRA_TRANSPORT_PARAMETER_LEN,
        MAX_EXTRA_TRANSPORT_PARAMETERS, MIN_ACK_DELAY_DRAFT07, ServerConfig, TransportConfig,
        TransportParameterLayout, TransportParameterOrder, VERSION_INFORMATION_ID,
        VersionInformation,
    },
    shared::ConnectionId,
};

/// RFC 9000's default `ack_delay_exponent`, used to decode a peer's ACK Delay when its
/// transport parameters don't include one. Must match `ack_delay_exponent`'s default in the
/// `apply_params!` list below (kept as a separate constant: that list's defaults are untyped
/// integer literals, inferred as `u32` or `u64` depending on where each is used, which a named
/// constant with one fixed type can't be).
pub(crate) const DEFAULT_ACK_DELAY_EXPONENT: u32 = 3;

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that
// takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // #[doc] name (id) = default,
            /// Milliseconds, disabled if zero
            max_idle_timeout(MaxIdleTimeout) = 0,
            /// Limits the size of UDP payloads that the endpoint is willing to receive
            max_udp_payload_size(MaxUdpPayloadSize) = 65527,

            /// Initial value for the maximum amount of data that can be sent on the connection
            initial_max_data(InitialMaxData) = 0,
            /// Initial flow control limit for locally-initiated bidirectional streams
            initial_max_stream_data_bidi_local(InitialMaxStreamDataBidiLocal) = 0,
            /// Initial flow control limit for peer-initiated bidirectional streams
            initial_max_stream_data_bidi_remote(InitialMaxStreamDataBidiRemote) = 0,
            /// Initial flow control limit for unidirectional streams
            initial_max_stream_data_uni(InitialMaxStreamDataUni) = 0,

            /// Initial maximum number of bidirectional streams the peer may initiate
            initial_max_streams_bidi(InitialMaxStreamsBidi) = 0,
            /// Initial maximum number of unidirectional streams the peer may initiate
            initial_max_streams_uni(InitialMaxStreamsUni) = 0,

            /// Exponent used to decode the ACK Delay field in the ACK frame
            ack_delay_exponent(AckDelayExponent) = 3,
            /// Maximum amount of time in milliseconds by which the endpoint will delay sending
            /// acknowledgments
            max_ack_delay(MaxAckDelay) = 25,
            /// Maximum number of connection IDs from the peer that an endpoint is willing to store
            active_connection_id_limit(ActiveConnectionIdLimit) = 2,
        }
    };
}

macro_rules! make_struct {
    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
        /// Transport parameters used to negotiate connection-level preferences between peers
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $($(#[$doc])* pub(crate) $name : VarInt,)*

            /// Does the endpoint support active connection migration
            pub(crate) disable_active_migration: bool,
            /// Maximum size for datagram frames
            pub(crate) max_datagram_frame_size: Option<VarInt>,
            /// The value that the endpoint included in the Source Connection ID field of the first
            /// Initial packet it sends for the connection
            pub(crate) initial_src_cid: Option<ConnectionId>,
            /// The endpoint is willing to receive QUIC packets containing any value for the fixed
            /// bit
            pub(crate) grease_quic_bit: bool,

            /// Minimum amount of time in microseconds by which the endpoint is able to delay
            /// sending acknowledgments
            ///
            /// If a value is provided, it implies that the endpoint supports QUIC Acknowledgement
            /// Frequency
            pub(crate) min_ack_delay: Option<VarInt>,

            // Server-only
            /// The value of the Destination Connection ID field from the first Initial packet sent
            /// by the client
            pub(crate) original_dst_cid: Option<ConnectionId>,
            /// The value that the server included in the Source Connection ID field of a Retry
            /// packet
            pub(crate) retry_src_cid: Option<ConnectionId>,
            /// Token used by the client to verify a stateless reset from the server
            pub(crate) stateless_reset_token: Option<ResetToken>,
            /// The server's preferred address for communication after handshake completion
            pub(crate) preferred_address: Option<PreferredAddress>,
            /// The randomly generated reserved transport parameter to sustain future extensibility
            /// of transport parameter extensions.
            /// When present, it is included during serialization but ignored during deserialization.
            pub(crate) grease_transport_parameter: Option<ReservedTransportParameter>,

            /// Codepoint under which `min_ack_delay` is serialized
            pub(crate) min_ack_delay_id: VarInt,
            /// `version_information` (RFC 9368): sent if configured or if QUIC version 2 is in
            /// use; the peer's is only acted on by endpoints that send one themselves
            pub(crate) version_information: Option<VersionInformationParameter>,
            /// Parameters copied verbatim from the configuration, included during serialization
            /// only
            pub(crate) extra_parameters:
                [Option<RawTransportParameter>; MAX_EXTRA_TRANSPORT_PARAMETERS],

            /// Defines the order in which transport parameters are serialized, as indices of
            /// serialization slots (see [`WriteSlot`])
            ///
            /// This field is initialized only for outgoing `TransportParameters` instances and
            /// is set to `None` for `TransportParameters` received from a peer.
            pub(crate) write_order: Option<[u8; WRITE_SLOTS]>,
        }

        // We deliberately don't implement the `Default` trait, since that would be public, and
        // downstream crates should never construct `TransportParameters` except by decoding those
        // supplied by a peer.
        impl TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            pub(crate) fn default() -> Self {
                Self {
                    $($name: VarInt::from_u32($default),)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,
                    initial_src_cid: None,
                    grease_quic_bit: false,
                    min_ack_delay: None,

                    original_dst_cid: None,
                    retry_src_cid: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                    grease_transport_parameter: None,
                    min_ack_delay_id: VarInt::from_u64(MIN_ACK_DELAY_DRAFT07).unwrap(),
                    version_information: None,
                    extra_parameters: [None; MAX_EXTRA_TRANSPORT_PARAMETERS],
                    write_order: None,
                }
            }
        }
    }
}

apply_params!(make_struct);

impl TransportParameters {
    pub(crate) fn new(
        config: &TransportConfig,
        endpoint_config: &EndpointConfig,
        cid_gen: &dyn ConnectionIdGenerator,
        initial_src_cid: ConnectionId,
        server_config: Option<&ServerConfig>,
        version: u32,
        rng: &mut impl RngCore,
    ) -> Self {
        let layout = &config.transport_parameter_layout;
        let windows = config.stream_receive_windows();
        let mut params = Self {
            initial_src_cid: Some(initial_src_cid),
            initial_max_streams_bidi: config.max_concurrent_bidi_streams,
            initial_max_streams_uni: config.max_concurrent_uni_streams,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: windows.bidi_local,
            initial_max_stream_data_bidi_remote: windows.bidi_remote,
            initial_max_stream_data_uni: windows.uni,
            max_udp_payload_size: endpoint_config.max_udp_payload_size,
            max_idle_timeout: config.max_idle_timeout.unwrap_or(VarInt(0)),
            // Rounded up, so that the peer never expects a shorter delay than we might take
            max_ack_delay: VarInt::from_u64(config.max_ack_delay.as_micros().div_ceil(1000) as u64)
                .unwrap(),
            disable_active_migration: server_config.is_some_and(|c| !c.migration),
            active_connection_id_limit: if cid_gen.cid_len() == 0
                && !layout.connection_id_limit_with_empty_cid
            {
                2 // i.e. default, i.e. unsent
            } else {
                config.remote_cid_limit()
            }
            .into(),
            max_datagram_frame_size: config
                .datagram_receive_buffer_size
                .map(|buffer| match config.max_datagram_frame_size {
                    Some(size) => size.min(VarInt::from_u64(buffer as u64).unwrap_or(VarInt::MAX)),
                    None => (buffer.min(u16::MAX.into()) as u16).into(),
                }),
            grease_quic_bit: endpoint_config.grease_quic_bit,
            min_ack_delay: layout.min_ack_delay_id.map(|_| {
                VarInt::from_u64(u64::try_from(TIMER_GRANULARITY.as_micros()).unwrap()).unwrap()
            }),
            min_ack_delay_id: layout
                .min_ack_delay_id
                .unwrap_or(VarInt::from_u64(MIN_ACK_DELAY_DRAFT07).unwrap()),
            grease_transport_parameter: layout
                .grease
                .then(|| ReservedTransportParameter::random(rng)),
            ..Self::default()
        };
        // RFC 9369, section 4: endpoints that support version 2 send version_information
        let supports_v2 = match server_config {
            None => version == QUIC_VERSION_2,
            Some(_) => endpoint_config.supported_versions.contains(&QUIC_VERSION_2),
        };
        let info = match &layout.version_information {
            Some(info) => Some(info.clone()),
            None if supports_v2 && server_config.is_some() => Some(VersionInformation::new(
                endpoint_config.supported_versions.clone(),
            )),
            None if supports_v2 => Some(VersionInformation::new(vec![version])),
            None => None,
        };
        if let Some(info) = &info {
            params.version_information = Some(VersionInformationParameter::new(info, version, rng));
        }
        for (slot, (id, value)) in params.extra_parameters.iter_mut().zip(&layout.extra) {
            *slot = Some(RawTransportParameter::new(*id, value));
        }
        params.write_order = Some(params.compute_write_order(layout, rng));
        params
    }

    /// Choose the serialization order of the parameters according to `layout`
    fn compute_write_order(
        &self,
        layout: &TransportParameterLayout,
        rng: &mut impl RngCore,
    ) -> [u8; WRITE_SLOTS] {
        let mut order = std::array::from_fn(|i| i as u8);
        match &layout.order {
            TransportParameterOrder::Random => {
                if self.version_information.is_none() && self.extra_parameters[0].is_none() {
                    // Only the upstream parameters can be present: shuffle exactly those, which
                    // consumes the same randomness as upstream Quinn
                    order[..TransportParameterId::SUPPORTED.len()].shuffle(rng);
                } else {
                    order.shuffle(rng);
                }
            }
            TransportParameterOrder::Fixed(ids) => {
                let mut taken = [false; WRITE_SLOTS];
                let mut n = 0;
                for id in ids {
                    let found = (0..WRITE_SLOTS)
                        .find(|&slot| !taken[slot] && self.slot_id(slot) == Some(id.into_inner()));
                    if let Some(slot) = found {
                        taken[slot] = true;
                        order[n] = slot as u8;
                        n += 1;
                    }
                }
                for slot in self.remaining_slots_by_id(&taken) {
                    order[n] = slot as u8;
                    n += 1;
                }
            }
            TransportParameterOrder::Rotated(ids) => {
                let mut taken = [false; WRITE_SLOTS];
                let mut listed = Vec::new();
                for id in ids {
                    let found = (0..WRITE_SLOTS).find(|&slot| {
                        !taken[slot]
                            && self.slot_id(slot) == Some(id.into_inner())
                            && self.slot_is_sent(slot)
                    });
                    if let Some(slot) = found {
                        taken[slot] = true;
                        listed.push(slot);
                    }
                }
                if !listed.is_empty() {
                    let start = (rng.next_u32() as usize) % listed.len();
                    listed.rotate_left(start);
                }
                let rest = self.remaining_slots_by_id(&taken);
                for (n, slot) in listed.into_iter().chain(rest).enumerate() {
                    order[n] = slot as u8;
                }
            }
        }
        order
    }

    /// The slots not marked in `taken`, sorted by [`Self::slot_id`] (unknown-id slots last)
    fn remaining_slots_by_id(&self, taken: &[bool; WRITE_SLOTS]) -> Vec<usize> {
        let mut rest = (0..WRITE_SLOTS)
            .filter(|&slot| !taken[slot])
            .collect::<Vec<_>>();
        rest.sort_by_key(|&slot| self.slot_id(slot).unwrap_or(u64::MAX));
        rest
    }

    /// Whether the given slot writes anything
    fn slot_is_sent(&self, slot: usize) -> bool {
        let mut buf = Vec::new();
        self.write_slot(slot as u8, &mut buf);
        !buf.is_empty()
    }

    /// Identifier serialized for the given slot, if it can be determined
    fn slot_id(&self, slot: usize) -> Option<u64> {
        match WriteSlot::from_index(slot) {
            WriteSlot::Standard(TransportParameterId::ReservedTransportParameter) => {
                self.grease_transport_parameter.map(|x| x.id.into_inner())
            }
            WriteSlot::Standard(TransportParameterId::MinAckDelayDraft07) => {
                Some(self.min_ack_delay_id.into_inner())
            }
            WriteSlot::Standard(id) => Some(id as u64),
            WriteSlot::VersionInformation => Some(VERSION_INFORMATION_ID),
            WriteSlot::Extra(i) => self.extra_parameters[i].map(|x| x.id.into_inner()),
        }
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub(crate) fn validate_resumption_from(&self, cached: &Self) -> Result<(), TransportError> {
        if cached.active_connection_id_limit > self.active_connection_id_limit
            || cached.initial_max_data > self.initial_max_data
            || cached.initial_max_stream_data_bidi_local > self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote > self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni > self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi > self.initial_max_streams_bidi
            || cached.initial_max_streams_uni > self.initial_max_streams_uni
            || cached.max_datagram_frame_size > self.max_datagram_frame_size
            || cached.grease_quic_bit && !self.grease_quic_bit
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }

    /// Maximum number of CIDs to issue to this peer
    ///
    /// Consider both a) the active_connection_id_limit from the other end; and
    /// b) LOC_CID_COUNT used locally
    pub(crate) fn issue_cids_limit(&self) -> u64 {
        self.active_connection_id_limit.0.min(LOC_CID_COUNT)
    }
}

/// A server's preferred address
///
/// This is communicated as a transport parameter during TLS session establishment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct PreferredAddress {
    pub(crate) address_v4: Option<SocketAddrV4>,
    pub(crate) address_v6: Option<SocketAddrV6>,
    pub(crate) connection_id: ConnectionId,
    pub(crate) stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        w.write(self.address_v4.map_or(Ipv4Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v4.map_or(0, |x| x.port()));
        w.write(self.address_v6.map_or(Ipv6Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v6.map_or(0, |x| x.port()));
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        let ip_v4 = r.get::<Ipv4Addr>()?;
        let port_v4 = r.get::<u16>()?;
        let ip_v6 = r.get::<Ipv6Addr>()?;
        let port_v6 = r.get::<u16>()?;
        let cid_len = r.get::<u8>()?;
        if r.remaining() < cid_len as usize || cid_len > MAX_CID_SIZE as u8 {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; RESET_TOKEN_SIZE];
        r.copy_to_slice(&mut token);
        let address_v4 = if ip_v4.is_unspecified() && port_v4 == 0 {
            None
        } else {
            Some(SocketAddrV4::new(ip_v4, port_v4))
        };
        let address_v6 = if ip_v6.is_unspecified() && port_v6 == 0 {
            None
        } else {
            Some(SocketAddrV6::new(ip_v6, port_v6, 0, 0))
        };
        if address_v4.is_none() && address_v6.is_none() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            address_v4,
            address_v6,
            connection_id: cid,
            stateless_reset_token: token.into(),
        })
    }
}

/// Errors encountered while decoding `TransportParameters`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum Error {
    /// Parameters that are semantically invalid
    #[error("parameter had illegal value")]
    IllegalValue,
    /// Catch-all error for problems while decoding transport parameters
    #[error("parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::IllegalValue => Self::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => Self::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Self::Malformed
    }
}

impl TransportParameters {
    /// Encode `TransportParameters` into buffer
    pub fn write<W: BufMut>(&self, w: &mut W) {
        for idx in self
            .write_order
            .as_ref()
            .unwrap_or(&std::array::from_fn(|i| i as u8))
        {
            self.write_slot(*idx, w);
        }
    }

    /// Encode the parameter of one serialization slot, if it is sent
    fn write_slot<W: BufMut>(&self, idx: u8, w: &mut W) {
        let id = match WriteSlot::from_index(idx as usize) {
            WriteSlot::Standard(id) => id,
            WriteSlot::VersionInformation => {
                if let Some(ref info) = self.version_information {
                    info.write(w);
                }
                return;
            }
            WriteSlot::Extra(i) => {
                if let Some(ref param) = self.extra_parameters[i] {
                    param.write(w);
                }
                return;
            }
        };
        match id {
            TransportParameterId::ReservedTransportParameter => {
                if let Some(param) = self.grease_transport_parameter {
                    param.write(w);
                }
            }
            TransportParameterId::StatelessResetToken => {
                if let Some(ref x) = self.stateless_reset_token {
                    w.write_var(id as u64);
                    w.write_var(16);
                    w.put_slice(x);
                }
            }
            TransportParameterId::DisableActiveMigration => {
                if self.disable_active_migration {
                    w.write_var(id as u64);
                    w.write_var(0);
                }
            }
            TransportParameterId::MaxDatagramFrameSize => {
                if let Some(x) = self.max_datagram_frame_size {
                    w.write_var(id as u64);
                    w.write_var(x.size() as u64);
                    w.write(x);
                }
            }
            TransportParameterId::PreferredAddress => {
                if let Some(ref x) = self.preferred_address {
                    w.write_var(id as u64);
                    w.write_var(x.wire_size() as u64);
                    x.write(w);
                }
            }
            TransportParameterId::OriginalDestinationConnectionId => {
                if let Some(ref cid) = self.original_dst_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::InitialSourceConnectionId => {
                if let Some(ref cid) = self.initial_src_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::RetrySourceConnectionId => {
                if let Some(ref cid) = self.retry_src_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::GreaseQuicBit => {
                if self.grease_quic_bit {
                    w.write_var(id as u64);
                    w.write_var(0);
                }
            }
            TransportParameterId::MinAckDelayDraft07 => {
                if let Some(x) = self.min_ack_delay {
                    w.write(self.min_ack_delay_id);
                    w.write_var(x.size() as u64);
                    w.write(x);
                }
            }
            id => {
                macro_rules! write_params {
                    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                        match id {
                            $(TransportParameterId::$id => {
                                if self.$name.0 != $default {
                                    w.write_var(id as u64);
                                    w.write(VarInt::try_from(self.$name.size()).unwrap());
                                    w.write(self.$name);
                                }
                            })*,
                            _ => {
                                unimplemented!("Missing implementation of write for transport parameter with code {id:?}");
                            }
                        }
                    }
                }
                apply_params!(write_params);
            }
        }
    }

    /// Encode only the transport parameters a split Encrypted Client Hello
    /// sends in its ClientHelloOuter, mirroring Firefox's neqo
    /// (`neqo_transport::tparams::TransportParameters::filter_ch_outer`):
    /// the outer hello is a fallback the server only completes if it cannot
    /// or will not accept the real (inner, encrypted) one, so most
    /// parameters (the ones about streams, flow control and migration)
    /// would be meaningless there and would leak real, distinguishing
    /// values through a hello otherwise meant to look generic. neqo's own
    /// allowlist has 8 entries, but for a stock client only three ever hold
    /// a value (the rest are server-only or never set to a non-default
    /// one): `max_ack_delay`, `initial_src_cid` and `version_information`,
    /// in ascending transport parameter ID order. This never changes the
    /// real set `write` encodes for the inner hello.
    pub fn write_ech_outer<W: BufMut>(&self, w: &mut W) {
        if self.max_ack_delay.0 != 25 {
            w.write_var(TransportParameterId::MaxAckDelay as u64);
            w.write_var(self.max_ack_delay.size() as u64);
            w.write(self.max_ack_delay);
        }
        if let Some(ref cid) = self.initial_src_cid {
            w.write_var(TransportParameterId::InitialSourceConnectionId as u64);
            w.write_var(cid.len() as u64);
            w.put_slice(cid);
        }
        if let Some(ref info) = self.version_information {
            info.write(w);
        }
    }

    /// Decode `TransportParameters` from buffer
    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = Self::default();

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {{
                struct ParamState {
                    $($name: bool,)*
                }

                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(param_state);

        while r.has_remaining() {
            let id = r.get_var()?;
            let len = r.get_var()?;
            if (r.remaining() as u64) < len {
                return Err(Error::Malformed);
            }
            let len = len as usize;
            if id == VERSION_INFORMATION_ID {
                let value = r.copy_to_bytes(len);
                params.version_information = Some(match params.version_information {
                    // A repeated parameter is malformed (RFC 9000, section 7.4)
                    Some(_) => VersionInformationParameter::read(side, &[]),
                    None => VersionInformationParameter::read(side, &value),
                });
                continue;
            }
            let Ok(id) = TransportParameterId::try_from(id) else {
                // unknown transport parameters are ignored
                r.advance(len);
                continue;
            };

            match id {
                TransportParameterId::OriginalDestinationConnectionId => {
                    decode_cid(len, &mut params.original_dst_cid, r)?
                }
                TransportParameterId::StatelessResetToken => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                TransportParameterId::DisableActiveMigration => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                TransportParameterId::PreferredAddress => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.preferred_address = Some(PreferredAddress::read(&mut r.take(len))?);
                }
                TransportParameterId::InitialSourceConnectionId => {
                    decode_cid(len, &mut params.initial_src_cid, r)?
                }
                TransportParameterId::RetrySourceConnectionId => {
                    decode_cid(len, &mut params.retry_src_cid, r)?
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(r.get().unwrap());
                }
                TransportParameterId::GreaseQuicBit => match len {
                    0 => params.grease_quic_bit = true,
                    _ => return Err(Error::Malformed),
                },
                TransportParameterId::MinAckDelayDraft07 => {
                    params.min_ack_delay = Some(r.get().unwrap())
                }
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id => {
                                    let value = r.get::<VarInt>()?;
                                    if len != value.size() || got.$name { return Err(Error::Malformed); }
                                    params.$name = value.into();
                                    got.$name = true;
                                })*
                                _ => r.advance(len),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.26.1
        if params.ack_delay_exponent.0 > 20
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.28.1
            || params.max_ack_delay.0 >= 1 << 14
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-6.2.1
            || params.active_connection_id_limit.0 < 2
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.10.1
            || params.max_udp_payload_size.0 < 1200
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-2
            || params.initial_max_streams_bidi.0 > MAX_STREAM_COUNT
            || params.initial_max_streams_uni.0 > MAX_STREAM_COUNT
            // https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-08.html#section-3-4
            || params.min_ack_delay.is_some_and(|min_ack_delay| {
                // min_ack_delay uses microseconds, whereas max_ack_delay uses milliseconds
                min_ack_delay.0 > params.max_ack_delay.0 * 1_000
            })
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-8
            || (side.is_server()
                && (params.original_dst_cid.is_some()
                    || params.preferred_address.is_some()
                    || params.retry_src_cid.is_some()
                    || params.stateless_reset_token.is_some()))
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.38.1
            || params
                .preferred_address.is_some_and(|x| x.connection_id.is_empty())
        {
            return Err(Error::IllegalValue);
        }

        Ok(params)
    }
}

/// Number of serialization slots: the parameters Quinn knows, `version_information` and the extra
/// parameters from the configuration
const WRITE_SLOTS: usize =
    TransportParameterId::SUPPORTED.len() + 1 + MAX_EXTRA_TRANSPORT_PARAMETERS;

/// What a serialization slot of [`TransportParameters::write_order`] refers to
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum WriteSlot {
    /// A parameter from [`TransportParameterId::SUPPORTED`]
    Standard(TransportParameterId),
    /// `version_information`
    VersionInformation,
    /// An entry of [`TransportParameters::extra_parameters`]
    Extra(usize),
}

impl WriteSlot {
    fn from_index(index: usize) -> Self {
        let supported = TransportParameterId::SUPPORTED.len();
        match index {
            i if i < supported => Self::Standard(TransportParameterId::SUPPORTED[i]),
            i if i == supported => Self::VersionInformation,
            i => Self::Extra(i - supported - 1),
        }
    }
}

/// The `version_information` transport parameter (RFC 9368)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct VersionInformationParameter {
    chosen: u32,
    /// The available versions; of a received parameter, the first [`MAX_AVAILABLE_VERSIONS`]
    available: [u32; MAX_AVAILABLE_VERSIONS],
    len: u8,
    /// Whether the parameter is well-formed (RFC 9368, section 4); a sent one always is
    valid: bool,
}

impl VersionInformationParameter {
    /// Resolve the configured content, drawing the GREASE version and its position from `rng`
    fn new(config: &VersionInformation, version: u32, rng: &mut impl RngCore) -> Self {
        // Reserved versions have the form 0x?a?a?a?a (RFC 9000, section 15)
        fn grease_version(rng: &mut impl RngCore) -> u32 {
            rng.next_u32() & 0xf0f0_f0f0 | 0x0a0a_0a0a
        }
        let mut list = config.available.clone();
        match config.grease {
            GreaseVersion::None => {}
            GreaseVersion::At(index) => {
                let value = grease_version(rng);
                list.insert(index.min(list.len()), value);
            }
            GreaseVersion::Random => {
                let index = rng.random_range(0..=list.len());
                let value = grease_version(rng);
                list.insert(index, value);
            }
        }
        list.truncate(MAX_AVAILABLE_VERSIONS);
        let mut available = [0; MAX_AVAILABLE_VERSIONS];
        available[..list.len()].copy_from_slice(&list);
        Self {
            chosen: version,
            available,
            len: list.len() as u8,
            valid: true,
        }
    }

    /// Decode a parameter received by `side`
    ///
    /// Never fails: a malformed parameter is marked as such, and only endpoints that take part in
    /// version negotiation reject it.
    pub(crate) fn read(side: Side, value: &[u8]) -> Self {
        let mut this = Self {
            chosen: 0,
            available: [0; MAX_AVAILABLE_VERSIONS],
            len: 0,
            valid: false,
        };
        if value.len() < 4 || value.len() % 4 != 0 {
            return this;
        }
        let mut versions = value
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().unwrap()));
        this.chosen = versions.next().unwrap();
        let mut valid = this.chosen != 0;
        let mut listed = false;
        for version in versions {
            valid &= version != 0;
            listed |= version == this.chosen;
            if usize::from(this.len) < MAX_AVAILABLE_VERSIONS {
                this.available[usize::from(this.len)] = version;
                this.len += 1;
            }
        }
        // A client's chosen version must be among its available versions
        this.valid = valid && (side.is_client() || listed);
        this
    }

    pub(crate) fn chosen(&self) -> u32 {
        self.chosen
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    /// Whether `version` is among the available versions
    pub(crate) fn lists(&self, version: u32) -> bool {
        self.available[..usize::from(self.len)].contains(&version)
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write_var(VERSION_INFORMATION_ID);
        w.write_var(4 + 4 * u64::from(self.len));
        w.write(self.chosen);
        for version in &self.available[..usize::from(self.len)] {
            w.write(*version);
        }
    }
}

/// A transport parameter written verbatim from the configuration
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct RawTransportParameter {
    id: VarInt,
    len: u8,
    value: [u8; MAX_EXTRA_TRANSPORT_PARAMETER_LEN],
}

impl RawTransportParameter {
    fn new(id: VarInt, value: &[u8]) -> Self {
        let len = value.len().min(MAX_EXTRA_TRANSPORT_PARAMETER_LEN);
        let mut buf = [0; MAX_EXTRA_TRANSPORT_PARAMETER_LEN];
        buf[..len].copy_from_slice(&value[..len]);
        Self {
            id,
            len: len as u8,
            value: buf,
        }
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write(self.id);
        w.write_var(u64::from(self.len));
        w.put_slice(&self.value[..usize::from(self.len)]);
    }
}

/// A reserved transport parameter.
///
/// It has an identifier of the form 31 * N + 27 for the integer value of N.
/// Such identifiers are reserved to exercise the requirement that unknown transport parameters be ignored.
/// The reserved transport parameter has no semantics and can carry arbitrary values.
/// It may be included in transport parameters sent to the peer, and should be ignored when received.
///
/// See spec: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1>
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ReservedTransportParameter {
    /// The reserved identifier of the transport parameter
    id: VarInt,

    /// Buffer to store the parameter payload
    payload: [u8; Self::MAX_PAYLOAD_LEN],

    /// The number of bytes to include in the wire format from the `payload` buffer
    payload_len: usize,
}

impl ReservedTransportParameter {
    /// Generates a transport parameter with a random payload and a reserved ID.
    ///
    /// The implementation is inspired by quic-go and quiche:
    /// 1. <https://github.com/quic-go/quic-go/blob/3e0a67b2476e1819752f04d75968de042b197b56/internal/wire/transport_parameters.go#L338-L344>
    /// 2. <https://github.com/google/quiche/blob/cb1090b20c40e2f0815107857324e99acf6ec567/quiche/quic/core/crypto/transport_parameters.cc#L843-L860>
    fn random(rng: &mut impl RngCore) -> Self {
        let id = Self::generate_reserved_id(rng);

        let payload_len = rng.random_range(0..Self::MAX_PAYLOAD_LEN);

        let payload = {
            let mut slice = [0u8; Self::MAX_PAYLOAD_LEN];
            rng.fill_bytes(&mut slice[..payload_len]);
            slice
        };

        Self {
            id,
            payload,
            payload_len,
        }
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write_var(self.id.0);
        w.write_var(self.payload_len as u64);
        w.put_slice(&self.payload[..self.payload_len]);
    }

    /// Generates a random reserved identifier of the form `31 * N + 27`, as required by RFC 9000.
    /// Reserved transport parameter identifiers are used to test compliance with the requirement
    /// that unknown transport parameters must be ignored by peers.
    /// See: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1> and <https://www.rfc-editor.org/rfc/rfc9000.html#section-22.3>
    fn generate_reserved_id(rng: &mut impl RngCore) -> VarInt {
        let id = {
            let rand = rng.random_range(0u64..(1 << 62) - 27);
            let n = rand / 31;
            31 * n + 27
        };
        debug_assert!(
            id % 31 == 27,
            "generated id does not have the form of 31 * N + 27"
        );
        VarInt::from_u64(id).expect(
            "generated id does fit into range of allowed transport parameter IDs: [0; 2^62)",
        )
    }

    /// The maximum length of the payload to include as the parameter payload.
    /// This value is not a specification-imposed limit but is chosen to match
    /// the limit used by other implementations of QUIC, e.g., quic-go and quiche.
    const MAX_PAYLOAD_LEN: usize = 16;
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportParameterId {
    // https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table
    OriginalDestinationConnectionId = 0x00,
    MaxIdleTimeout = 0x01,
    StatelessResetToken = 0x02,
    MaxUdpPayloadSize = 0x03,
    InitialMaxData = 0x04,
    InitialMaxStreamDataBidiLocal = 0x05,
    InitialMaxStreamDataBidiRemote = 0x06,
    InitialMaxStreamDataUni = 0x07,
    InitialMaxStreamsBidi = 0x08,
    InitialMaxStreamsUni = 0x09,
    AckDelayExponent = 0x0A,
    MaxAckDelay = 0x0B,
    DisableActiveMigration = 0x0C,
    PreferredAddress = 0x0D,
    ActiveConnectionIdLimit = 0x0E,
    InitialSourceConnectionId = 0x0F,
    RetrySourceConnectionId = 0x10,

    // Smallest possible ID of reserved transport parameter https://datatracker.ietf.org/doc/html/rfc9000#section-22.3
    ReservedTransportParameter = 0x1B,

    // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    MaxDatagramFrameSize = 0x20,

    // https://www.rfc-editor.org/rfc/rfc9287.html#section-3
    GreaseQuicBit = 0x2AB2,

    // https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency#section-10.1
    MinAckDelayDraft07 = 0xFF04DE1B,
}

impl TransportParameterId {
    /// Array with all supported transport parameter IDs
    const SUPPORTED: [Self; 21] = [
        Self::MaxIdleTimeout,
        Self::MaxUdpPayloadSize,
        Self::InitialMaxData,
        Self::InitialMaxStreamDataBidiLocal,
        Self::InitialMaxStreamDataBidiRemote,
        Self::InitialMaxStreamDataUni,
        Self::InitialMaxStreamsBidi,
        Self::InitialMaxStreamsUni,
        Self::AckDelayExponent,
        Self::MaxAckDelay,
        Self::ActiveConnectionIdLimit,
        Self::ReservedTransportParameter,
        Self::StatelessResetToken,
        Self::DisableActiveMigration,
        Self::MaxDatagramFrameSize,
        Self::PreferredAddress,
        Self::OriginalDestinationConnectionId,
        Self::InitialSourceConnectionId,
        Self::RetrySourceConnectionId,
        Self::GreaseQuicBit,
        Self::MinAckDelayDraft07,
    ];
}

impl std::cmp::PartialEq<u64> for TransportParameterId {
    fn eq(&self, other: &u64) -> bool {
        *other == (*self as u64)
    }
}

impl TryFrom<u64> for TransportParameterId {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let param = match value {
            id if Self::MaxIdleTimeout == id => Self::MaxIdleTimeout,
            id if Self::MaxUdpPayloadSize == id => Self::MaxUdpPayloadSize,
            id if Self::InitialMaxData == id => Self::InitialMaxData,
            id if Self::InitialMaxStreamDataBidiLocal == id => Self::InitialMaxStreamDataBidiLocal,
            id if Self::InitialMaxStreamDataBidiRemote == id => {
                Self::InitialMaxStreamDataBidiRemote
            }
            id if Self::InitialMaxStreamDataUni == id => Self::InitialMaxStreamDataUni,
            id if Self::InitialMaxStreamsBidi == id => Self::InitialMaxStreamsBidi,
            id if Self::InitialMaxStreamsUni == id => Self::InitialMaxStreamsUni,
            id if Self::AckDelayExponent == id => Self::AckDelayExponent,
            id if Self::MaxAckDelay == id => Self::MaxAckDelay,
            id if Self::ActiveConnectionIdLimit == id => Self::ActiveConnectionIdLimit,
            id if Self::ReservedTransportParameter == id => Self::ReservedTransportParameter,
            id if Self::StatelessResetToken == id => Self::StatelessResetToken,
            id if Self::DisableActiveMigration == id => Self::DisableActiveMigration,
            id if Self::MaxDatagramFrameSize == id => Self::MaxDatagramFrameSize,
            id if Self::PreferredAddress == id => Self::PreferredAddress,
            id if Self::OriginalDestinationConnectionId == id => {
                Self::OriginalDestinationConnectionId
            }
            id if Self::InitialSourceConnectionId == id => Self::InitialSourceConnectionId,
            id if Self::RetrySourceConnectionId == id => Self::RetrySourceConnectionId,
            id if Self::GreaseQuicBit == id => Self::GreaseQuicBit,
            id if Self::MinAckDelayDraft07 == id => Self::MinAckDelayDraft07,
            _ => return Err(()),
        };
        Ok(param)
    }
}

fn decode_cid(len: usize, value: &mut Option<ConnectionId>, r: &mut impl Buf) -> Result<(), Error> {
    if len > MAX_CID_SIZE || value.is_some() || r.remaining() < len {
        return Err(Error::Malformed);
    }

    *value = Some(ConnectionId::from_buf(r, len));
    Ok(())
}

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use rand::SeedableRng;

    use super::*;
    use crate::Duration;

    /// The serialization-only parameters (`version_information`, extra parameters) keep the
    /// struct small enough to copy
    #[test]
    fn size() {
        assert!(std::mem::size_of::<TransportParameters>() <= 640);
    }

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[])),
            original_dst_cid: Some(ConnectionId::new(&[])),
            initial_max_streams_bidi: 16u32.into(),
            initial_max_streams_uni: 16u32.into(),
            ack_delay_exponent: 2u32.into(),
            max_udp_payload_size: 1200u32.into(),
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 24, 0, 0)),
                connection_id: ConnectionId::new(&[0x42]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
            }),
            grease_quic_bit: true,
            min_ack_delay: Some(2_000u32.into()),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }

    #[test]
    fn reserved_transport_parameter_generate_reserved_id() {
        let mut rngs = [
            StepRng(0),
            StepRng(1),
            StepRng(27),
            StepRng(31),
            StepRng(u32::MAX as u64),
            StepRng(u32::MAX as u64 - 1),
            StepRng(u32::MAX as u64 + 1),
            StepRng(u32::MAX as u64 - 27),
            StepRng(u32::MAX as u64 + 27),
            StepRng(u32::MAX as u64 - 31),
            StepRng(u32::MAX as u64 + 31),
            StepRng(u64::MAX),
            StepRng(u64::MAX - 1),
            StepRng(u64::MAX - 27),
            StepRng(u64::MAX - 31),
            StepRng(1 << 62),
            StepRng((1 << 62) - 1),
            StepRng((1 << 62) + 1),
            StepRng((1 << 62) - 27),
            StepRng((1 << 62) + 27),
            StepRng((1 << 62) - 31),
            StepRng((1 << 62) + 31),
        ];
        for rng in &mut rngs {
            let id = ReservedTransportParameter::generate_reserved_id(rng);
            assert!(id.0 % 31 == 27)
        }
    }

    struct StepRng(u64);

    impl RngCore for StepRng {
        #[inline]
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        #[inline]
        fn next_u64(&mut self) -> u64 {
            let res = self.0;
            self.0 = self.0.wrapping_add(1);
            res
        }

        #[inline]
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            let mut left = dst;
            while left.len() >= 8 {
                let (l, r) = left.split_at_mut(8);
                left = r;
                l.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            let n = left.len();
            if n > 0 {
                left.copy_from_slice(&self.next_u32().to_le_bytes()[..n]);
            }
        }
    }

    #[test]
    fn reserved_transport_parameter_ignored_when_read() {
        let mut buf = Vec::new();
        let reserved_parameter = ReservedTransportParameter::random(&mut rand::rng());
        assert!(reserved_parameter.payload_len < ReservedTransportParameter::MAX_PAYLOAD_LEN);
        assert!(reserved_parameter.id.0 % 31 == 27);

        reserved_parameter.write(&mut buf);
        assert!(!buf.is_empty());
        let read_params = TransportParameters::read(Side::Server, &mut buf.as_slice()).unwrap();
        assert_eq!(read_params, TransportParameters::default());
    }

    #[test]
    fn read_semantic_validation() {
        #[allow(clippy::type_complexity)]
        let illegal_params_builders: Vec<Box<dyn FnMut(&mut TransportParameters)>> = vec![
            Box::new(|t| {
                // This min_ack_delay is bigger than max_ack_delay!
                let min_ack_delay = t.max_ack_delay.0 * 1_000 + 1;
                t.min_ack_delay = Some(VarInt::from_u64(min_ack_delay).unwrap())
            }),
            Box::new(|t| {
                // Preferred address can only be sent by senders (and we are reading the transport
                // params as a client)
                t.preferred_address = Some(PreferredAddress {
                    address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                    address_v6: None,
                    connection_id: ConnectionId::new(&[]),
                    stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
                })
            }),
        ];

        for mut builder in illegal_params_builders {
            let mut buf = Vec::new();
            let mut params = TransportParameters::default();
            builder(&mut params);
            params.write(&mut buf);

            assert_eq!(
                TransportParameters::read(Side::Server, &mut buf.as_slice()),
                Err(Error::IllegalValue)
            );
        }
    }

    #[test]
    fn resumption_params_validation() {
        let high_limit = TransportParameters {
            initial_max_streams_uni: 32u32.into(),
            ..TransportParameters::default()
        };
        let low_limit = TransportParameters {
            initial_max_streams_uni: 16u32.into(),
            ..TransportParameters::default()
        };
        high_limit.validate_resumption_from(&low_limit).unwrap();
        low_limit.validate_resumption_from(&high_limit).unwrap_err();
    }

    /// Split encoded transport parameters into `(id, value)` pairs, in wire order
    fn tlvs(mut buf: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        while buf.has_remaining() {
            let id = buf.get_var().unwrap();
            let len = buf.get_var().unwrap() as usize;
            out.push((id, buf[..len].to_vec()));
            buf.advance(len);
        }
        out
    }

    fn is_grease_version(version: &[u8]) -> bool {
        version.len() == 4 && version.iter().all(|b| b & 0x0f == 0x0a)
    }

    fn encode(
        transport: &TransportConfig,
        endpoint: &EndpointConfig,
        cid_len: usize,
        rng: &mut impl RngCore,
    ) -> (TransportParameters, Vec<u8>) {
        let mut cid_gen = crate::RandomConnectionIdGenerator::new(cid_len);
        let cid = cid_gen.generate_cid();
        let params = TransportParameters::new(transport, endpoint, &cid_gen, cid, None, 1, rng);
        let mut buf = Vec::new();
        params.write(&mut buf);
        (params, buf)
    }

    /// A received `version_information` is parsed leniently
    #[test]
    fn version_information_read() {
        let mut buf = Vec::new();
        for _ in 0..2 {
            buf.write_var(VERSION_INFORMATION_ID);
            buf.write_var(12);
            for version in [1, QUIC_VERSION_2, 1] {
                buf.write::<u32>(version);
            }
        }
        let params = TransportParameters::read(Side::Server, &mut &buf[..14]).unwrap();
        let info = params.version_information.unwrap();
        assert!(info.is_valid());
        assert_eq!(info.chosen(), 1);
        assert!(info.lists(QUIC_VERSION_2));
        // A repeated parameter is malformed but only rejected by version negotiation
        let params = TransportParameters::read(Side::Server, &mut &buf[..]).unwrap();
        assert!(!params.version_information.unwrap().is_valid());
        // A client's chosen version must be available, a server's need not
        let mut buf = Vec::new();
        buf.write_var(VERSION_INFORMATION_ID);
        buf.write_var(8);
        buf.write::<u32>(QUIC_VERSION_2);
        buf.write::<u32>(1);
        let read = |side| {
            let params = TransportParameters::read(side, &mut &buf[..]).unwrap();
            params.version_information.unwrap().is_valid()
        };
        assert!(!read(Side::Server));
        assert!(read(Side::Client));
    }

    /// Chrome 153's layout: shuffled order, one GREASE parameter, `version_information` with a
    /// GREASE version at a random position, `google_connection_options`, no `min_ack_delay` and
    /// no `grease_quic_bit`
    #[test]
    fn chrome_like_layout() {
        let transport = crate::test_profiles::chrome_transport();
        let endpoint = crate::test_profiles::chrome_endpoint();

        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let mut orders = std::collections::HashSet::new();
        let mut grease_positions = [0; 2];
        for _ in 0..64 {
            let (_, buf) = encode(&transport, &endpoint, 0, &mut rng);
            let tlvs = tlvs(&buf);
            orders.insert(tlvs.iter().map(|(id, _)| *id).collect::<Vec<_>>());

            let grease = tlvs
                .iter()
                .filter(|(id, _)| id % 31 == 27 && *id > 0x3128)
                .collect::<Vec<_>>();
            assert_eq!(grease.len(), 1);
            assert!(grease[0].1.len() < 16);
            let grease_len = VarInt(grease[0].0).size() + 1 + grease[0].1.len();

            let mut expected: Vec<(u64, Vec<u8>)> = vec![
                (0x01, vec![0x80, 0x00, 0x75, 0x30]),
                (0x03, vec![0x45, 0xc0]),
                (0x04, vec![0x80, 0xf0, 0x00, 0x00]),
                (0x05, vec![0x80, 0x60, 0x00, 0x00]),
                (0x06, vec![0x80, 0x60, 0x00, 0x00]),
                (0x07, vec![0x80, 0x60, 0x00, 0x00]),
                (0x08, vec![0x40, 0x64]),
                (0x09, vec![0x40, 0x67]),
                (0x0f, vec![]),
                (0x20, vec![0x80, 0x01, 0x00, 0x00]),
                (0x3128, b"ORIG".to_vec()),
            ];
            let mut actual = tlvs
                .iter()
                .filter(|(id, _)| *id != 0x11 && *id != grease[0].0)
                .cloned()
                .collect::<Vec<_>>();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);

            let versions = &tlvs.iter().find(|(id, _)| *id == 0x11).unwrap().1;
            assert_eq!(versions.len(), 12);
            assert_eq!(versions[..4], [0, 0, 0, 1]);
            match (&versions[4..8], &versions[8..]) {
                (v, [0, 0, 0, 1]) if is_grease_version(v) => grease_positions[0] += 1,
                ([0, 0, 0, 1], v) if is_grease_version(v) => grease_positions[1] += 1,
                _ => panic!("unexpected version list {versions:x?}"),
            }

            // Chrome sends 86 bytes when its GREASE parameter has a six-byte value under an
            // eight-byte ID
            assert_eq!(buf.len() - grease_len, 86 - (8 + 1 + 6));
        }
        assert!(orders.len() > 60, "order must be random");
        assert!(grease_positions.iter().all(|&n| n > 10));
    }

    /// Firefox 156's parameters, byte for byte apart from the random source connection ID and
    /// GREASE version
    #[test]
    fn firefox_like_layout() {
        let transport = crate::test_profiles::firefox_transport(1);
        let endpoint = crate::test_profiles::firefox_endpoint();

        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let (params, buf) = encode(&transport, &endpoint, 3, &mut rng);
        let scid = params.initial_src_cid.unwrap();
        let grease = &buf[55..59];
        assert!(is_grease_version(grease));
        #[rustfmt::skip]
        let expected = [
            &[0x01, 0x04, 0x80, 0x00, 0x75, 0x30][..],
            &[0x04, 0x04, 0x81, 0x80, 0x00, 0x00],
            &[0x05, 0x04, 0x80, 0xc0, 0x00, 0x00],
            &[0x06, 0x04, 0x80, 0x10, 0x00, 0x00],
            &[0x07, 0x04, 0x80, 0x10, 0x00, 0x00],
            &[0x08, 0x02, 0x40, 0x64],
            &[0x09, 0x02, 0x40, 0x64],
            &[0x0b, 0x01, 0x14],
            &[0x0e, 0x01, 0x08],
            &[0x0f, 0x03], &scid,
            &[0x11, 0x10, 0x00, 0x00, 0x00, 0x01], grease, &[0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00, 0x00, 0x01],
            &[0x1d, 0x00],
            &[0xc0, 0x00, 0x00, 0x00, 0xff, 0x02, 0xde, 0x1a, 0x02, 0x43, 0xe8],
            &[0x20, 0x04, 0x80, 0x00, 0xff, 0xff],
        ]
        .concat();
        assert_eq!(buf, expected);
        assert_eq!(buf.len(), 86);
    }

    /// Without a custom layout, parameters are shuffled with exactly the randomness upstream
    /// Quinn uses
    #[test]
    fn default_layout_is_upstream() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let mut upstream_rng = rng.clone();
        let (params, buf) = encode(
            &TransportConfig::default(),
            &EndpointConfig::default(),
            8,
            &mut rng,
        );
        ReservedTransportParameter::random(&mut upstream_rng);
        let mut order: [u8; TransportParameterId::SUPPORTED.len()] =
            std::array::from_fn(|i| i as u8);
        order.shuffle(&mut upstream_rng);
        let write_order = params.write_order.unwrap();
        assert_eq!(write_order[..order.len()], order);
        assert_eq!(rng.next_u64(), upstream_rng.next_u64());

        let ids = tlvs(&buf).into_iter().map(|(id, _)| id).collect::<Vec<_>>();
        assert!(ids.contains(&MIN_ACK_DELAY_DRAFT07));
        assert!(!ids.contains(&0x11));
        assert_eq!(
            ids.iter()
                .filter(|id| *id % 31 == 27 && **id > 0x20)
                .count(),
            1
        );
    }

    /// Safari's order: its parameters in one cyclic order from a random start, an unlisted one
    /// last; `active_connection_id_limit` despite empty connection IDs
    #[test]
    fn rotated_order() {
        let cycle = [0x01u64, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f];
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(None);
        transport.active_connection_id_limit(Some(64));
        transport.max_concurrent_bidi_streams(VarInt(0));
        transport.datagram_receive_buffer_size(None);
        let mut layout = TransportParameterLayout::default();
        layout
            .order(TransportParameterOrder::Rotated(
                cycle.iter().map(|&id| VarInt(id)).collect(),
            ))
            .grease(false)
            .connection_id_limit_with_empty_cid(true)
            .min_ack_delay(None)
            .unwrap()
            .extra_parameter(VarInt(0xff08_0808), vec![7])
            .unwrap();
        transport.transport_parameter_layout(layout);
        let mut endpoint = EndpointConfig::default();
        endpoint.max_udp_payload_size(65527).unwrap();
        endpoint.grease_quic_bit(false);
        let mut starts = std::collections::HashSet::new();
        for seed in 0..40 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let (_, buf) = encode(&transport, &endpoint, 0, &mut rng);
            let ids = tlvs(&buf).into_iter().map(|(id, _)| id).collect::<Vec<_>>();
            // Without max_idle_timeout: seven parameters of the cycle, the extra one last.
            assert_eq!(ids.len(), 8, "{ids:x?}");
            assert_eq!(ids[7], 0xff08_0808);
            let sent: Vec<u64> = cycle.iter().copied().filter(|id| *id != 0x01).collect();
            let start = sent.iter().position(|id| *id == ids[0]).unwrap();
            let mut rotated = sent.clone();
            rotated.rotate_left(start);
            assert_eq!(ids[..7], rotated[..], "{ids:x?}");
            starts.insert(ids[0]);
        }
        assert_eq!(starts.len(), 7, "every start occurs");
    }

    /// Unlisted parameters follow the listed ones in ascending order
    #[test]
    fn fixed_order_appends_unlisted() {
        let mut transport = TransportConfig::default();
        let mut layout = TransportParameterLayout::default();
        layout.order(TransportParameterOrder::Fixed(vec![
            VarInt::from_u32(0x20),
            VarInt::from_u32(0x1234), // not sent
            VarInt::from_u32(0x01),
        ]));
        transport.transport_parameter_layout(layout);
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let (_, buf) = encode(&transport, &EndpointConfig::default(), 8, &mut rng);
        let ids = tlvs(&buf).into_iter().map(|(id, _)| id).collect::<Vec<_>>();
        assert_eq!(ids[..2], [0x20, 0x01]);
        assert!(ids[2..].windows(2).all(|w| w[0] < w[1]), "{ids:x?}");
        // 0x01, 0x03 to 0x09, 0x0e, 0x0f, 0x20, grease_quic_bit, min_ack_delay and GREASE
        assert_eq!(ids.len(), 14);
    }

    #[test]
    fn layout_validation() {
        let mut layout = TransportParameterLayout::default();
        // Parameters Quinn writes itself
        for id in [0x00, 0x05, 0x10, 0x11, 0x20, 0x2ab2] {
            assert!(layout.extra_parameter(VarInt(id), Bytes::new()).is_err());
        }
        // The configured min_ack_delay codepoint
        assert!(
            layout
                .extra_parameter(VarInt(MIN_ACK_DELAY_DRAFT07), Bytes::new())
                .is_err()
        );
        assert!(
            layout
                .extra_parameter(VarInt(0x1d), vec![0; MAX_EXTRA_TRANSPORT_PARAMETER_LEN + 1])
                .is_err()
        );
        layout.extra_parameter(VarInt(0x1d), Bytes::new()).unwrap();
        assert!(layout.extra_parameter(VarInt(0x1d), Bytes::new()).is_err());
        assert!(layout.min_ack_delay(Some(VarInt(0x1d))).is_err());
        for id in 0..MAX_EXTRA_TRANSPORT_PARAMETERS as u64 - 1 {
            layout
                .extra_parameter(VarInt(0x4000 + id), Bytes::new())
                .unwrap();
        }
        assert!(
            layout
                .extra_parameter(VarInt(0x5000), Bytes::new())
                .is_err()
        );

        let mut versions = VersionInformation::new(vec![1; MAX_AVAILABLE_VERSIONS]);
        assert!(layout.version_information(Some(versions.clone())).is_ok());
        versions.grease(GreaseVersion::Random);
        assert!(layout.version_information(Some(versions)).is_err());
        let mut versions = VersionInformation::new(vec![1]);
        versions.grease(GreaseVersion::At(2));
        assert!(layout.version_information(Some(versions)).is_err());
    }

    /// The configured windows, `max_ack_delay` and connection ID limit are advertised
    #[test]
    fn transport_values() {
        let mut transport = TransportConfig::default();
        transport
            .stream_receive_window_uni(Some(1000u32.into()))
            .max_ack_delay(Duration::from_micros(20_500))
            .active_connection_id_limit(Some(1));
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let (params, _) = encode(&transport, &EndpointConfig::default(), 8, &mut rng);
        assert_eq!(params.initial_max_stream_data_uni, VarInt(1000));
        assert_eq!(
            params.initial_max_stream_data_bidi_local,
            transport.stream_receive_window
        );
        // Rounded up to whole milliseconds
        assert_eq!(params.max_ack_delay, VarInt(21));
        // Clamped to the minimum of 2, which is the default and therefore not sent
        assert_eq!(params.active_connection_id_limit, VarInt(2));
        // Zero-length connection IDs never advertise a limit
        transport.active_connection_id_limit(Some(8));
        let (params, _) = encode(&transport, &EndpointConfig::default(), 0, &mut rng);
        assert_eq!(params.active_connection_id_limit, VarInt(2));
        // Datagrams: the explicit size is capped by the receive buffer
        transport
            .datagram_receive_buffer_size(Some(1000))
            .max_datagram_frame_size(Some(65_536u32.into()));
        let (params, _) = encode(&transport, &EndpointConfig::default(), 8, &mut rng);
        assert_eq!(params.max_datagram_frame_size, Some(VarInt(1000)));
    }
}
