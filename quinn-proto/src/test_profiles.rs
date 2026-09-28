//! Chrome and Firefox as configured in the tests
//!
//! Values from captures of Chrome 153 (quiche) and Firefox 156 (neqo) connecting to
//! www.google.com; shared by the transport parameter and the wire behaviour tests.

use bytes::Bytes;

use crate::{
    AckDecimation, AckPolicy, BufferedPacketProcessing, CryptoFraming, Duration, EndpointConfig,
    FingerprintConfig, FirstPacketNumber, GreaseVersion, InitialPadding, PacketNumbering,
    PacketPadding, RandomConnectionIdGenerator, SpinBit, TransportConfig, TransportParameterLayout,
    TransportParameterOrder, VarInt, VersionInformation,
};

/// Profile values of Chrome 153 (quiche)
pub(crate) fn chrome_transport() -> TransportConfig {
    let mut versions = VersionInformation::new(vec![1]);
    versions.grease(GreaseVersion::Random);
    let mut layout = TransportParameterLayout::default();
    layout
        .min_ack_delay(None)
        .unwrap()
        .version_information(Some(versions))
        .unwrap()
        .extra_parameter(VarInt::from_u32(0x3128), &b"ORIG"[..])
        .unwrap();
    let mut fingerprint = FingerprintConfig::default();
    fingerprint
        .packet_numbering(PacketNumbering::Shared { first: 1 })
        .initial_padding(InitialPadding::Frames { size: 1250 })
        .crypto_framing(CryptoFraming::ChaosProtection)
        .spin_bit(SpinBit::Zero)
        .grease_fixed_bit(false)
        .early_key_update(false)
        .ack_decimation(Some(AckDecimation::default()))
        .ack_policy(AckPolicy::Quiche)
        .ack_each_datagram(true)
        .packet_padding(PacketPadding::Leading)
        .trailing_ping(true)
        .buffered_packet_processing(BufferedPacketProcessing::AfterFirst1rttData)
        .finished_with_first_data(true);
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(103u32.into())
        .receive_window(15_728_640u32.into())
        .stream_receive_window(6_291_456u32.into())
        .max_datagram_frame_size(Some(65_536u32.into()))
        .initial_mtu(1250)
        .mtu_discovery_config(None)
        .transport_parameter_layout(layout)
        .fingerprint(fingerprint);
    transport
}

pub(crate) fn chrome_endpoint() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config
        .cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)))
        .grease_quic_bit(false)
        .max_udp_payload_size(1472)
        .unwrap();
    config
}

/// Profile values of Firefox 156 (neqo), with a fixed first packet number
pub(crate) fn firefox_transport(first_initial: u64) -> TransportConfig {
    let mut versions = VersionInformation::new(vec![0x6b33_43cf, 1]);
    versions.grease(GreaseVersion::At(0));
    let mut layout = TransportParameterLayout::default();
    layout
        .order(TransportParameterOrder::Fixed(
            [
                0x01,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0b,
                0x0e,
                0x0f,
                0x11,
                0x1d,
                0xff02_de1a,
                0x20,
            ]
            .into_iter()
            .map(|id| VarInt::from_u64(id).unwrap())
            .collect(),
        ))
        .grease(false)
        .min_ack_delay(Some(VarInt::from_u32(0xff02_de1a)))
        .unwrap()
        .version_information(Some(versions))
        .unwrap()
        .extra_parameter(VarInt::from_u32(0x1d), Bytes::new())
        .unwrap();
    let mut fingerprint = FingerprintConfig::default();
    fingerprint
        .packet_numbering(PacketNumbering::Sequential {
            first_initial: FirstPacketNumber::Fixed(first_initial),
        })
        .initial_padding(InitialPadding::TrailingZeros { size: 1252 })
        .crypto_framing(CryptoFraming::SniSlicing)
        .spin_bit(SpinBit::Random)
        .early_key_update(false)
        .ack_each_datagram(true)
        .early_connection_ids(true)
        .trailing_ping(true);
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(100u32.into())
        .receive_window(25_165_824u32.into())
        .stream_receive_window_bidi_local(Some(12_582_912u32.into()))
        .stream_receive_window_bidi_remote(Some(1_048_576u32.into()))
        .stream_receive_window_uni(Some(1_048_576u32.into()))
        .max_ack_delay(Duration::from_millis(20))
        .active_connection_id_limit(Some(8))
        .datagram_receive_buffer_size(Some(65_535))
        .initial_mtu(1252)
        .mtu_discovery_config(None)
        .transport_parameter_layout(layout)
        .fingerprint(fingerprint);
    transport
}

pub(crate) fn firefox_endpoint() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config
        .cid_generator(|| Box::new(RandomConnectionIdGenerator::new(3)))
        .grease_quic_bit(false)
        // Accept the version 2 packets of a server that switches to the offered version 2
        .supported_versions(vec![1, crate::QUIC_VERSION_2])
        .max_udp_payload_size(65_527)
        .unwrap();
    config
}
