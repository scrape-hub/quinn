//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic in Quinn is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{
    any::Any,
    str,
    sync::Arc,
    task::{Poll, Waker},
};

use bytes::BytesMut;

use crate::{
    ConnectError, Side, TransportError, shared::ConnectionId,
    transport_parameters::TransportParameters,
};

/// Cryptography interface based on *ring*
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
pub mod rustls;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sync + 'static {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys;

    /// Get data negotiated during the handshake, if available
    ///
    /// Returns `None` until the connection emits `HandshakeDataReady`.
    fn handshake_data(&self) -> Option<Box<dyn Any>>;

    /// Get the peer's identity, if available
    fn peer_identity(&self) -> Option<Box<dyn Any>>;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
    ///
    /// On success, returns `true` iff `self.handshake_data()` has been populated.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError>;

    /// Continue a handshake that waits for work the session performs asynchronously
    ///
    /// A session may finish part of the handshake outside of [`read_handshake()`], e.g. verify the
    /// peer's certificate on another thread. While such work is outstanding, this method returns
    /// `Poll::Pending` and arranges for `waker` to be woken once the work is done; the connection
    /// then calls it again. `Poll::Ready(Ok(()))` means that nothing is outstanding (anymore): what
    /// the finished work produced is then available through [`write_handshake()`],
    /// [`is_handshaking()`], [`handshake_data()`] and [`transport_parameters()`], just as after
    /// [`read_handshake()`]. An error aborts the handshake like an error of `read_handshake()`.
    ///
    /// Called by the connection while it is handshaking: after it passed handshake data to
    /// [`read_handshake()`] and whenever its driver is polled (see
    /// [`Connection::poll_handshake()`](crate::Connection::poll_handshake)). While work is
    /// outstanding, `read_handshake()` may be called with more data, which the session has to
    /// accept or buffer. The default implementation never waits.
    ///
    /// A call while work is still outstanding replaces any waker an earlier call registered:
    /// only the most recently passed `waker` may ever be woken, never one from an earlier call.
    /// An implementation that keeps the first waker and ignores later ones can stall the
    /// connection silently if a later caller relies on that replacement.
    ///
    /// [`read_handshake()`]: Session::read_handshake
    /// [`write_handshake()`]: Session::write_handshake
    /// [`is_handshaking()`]: Session::is_handshaking
    /// [`handshake_data()`]: Session::handshake_data
    /// [`transport_parameters()`]: Session::transport_parameters
    fn poll_handshake(&mut self, waker: &Waker) -> Poll<Result<(), TransportError>> {
        let _ = waker;
        Poll::Ready(Ok(()))
    }

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>>;

    /// Verify the integrity of a retry packet
    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool;

    /// Switch a client session to another QUIC version during the handshake
    ///
    /// Compatible version negotiation (RFC 9368): a client that offers other versions in its
    /// `version_information` transport parameter learns from the server's first Initial packet
    /// that the server switched the connection to one of them, e.g. from QUIC version 1 to
    /// version 2 (RFC 9369). This method is then called before any of the server's handshake data
    /// is passed to [`read_handshake()`](Self::read_handshake). On success, [`initial_keys()`]
    /// and every key the session derives later use `version`. If the server's packet does not
    /// authenticate with the new Initial keys, the connection calls this method again with the
    /// original version.
    ///
    /// The default implementation cannot switch and returns an error; the connection then closes
    /// with `VERSION_NEGOTIATION_ERROR`.
    ///
    /// [`initial_keys()`]: Self::initial_keys
    fn set_version(&mut self, version: u32) -> Result<(), UnsupportedVersion> {
        let _ = version;
        Err(UnsupportedVersion)
    }

    /// Fill `output` with `output.len()` bytes of keying material derived
    /// from the [Session]'s secrets, using `label` and `context` for domain
    /// separation.
    ///
    /// This function will fail, returning [ExportKeyingMaterialError],
    /// if the requested output length is too large.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError>;
}

/// A pair of keys for bidirectional communication
pub struct KeyPair<T> {
    /// Key for encrypting data
    pub local: T,
    /// Key for decrypting data
    pub remote: T,
}

/// A complete set of keys for a certain packet space
pub struct Keys {
    /// Header protection keys
    pub header: KeyPair<Box<dyn HeaderKey>>,
    /// Packet protection keys
    pub packet: KeyPair<Box<dyn PacketKey>>,
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16];

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session>;
}

/// Keys used to protect packet payloads
pub trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers
pub trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

/// A key for signing with HMAC-based algorithms
pub trait HmacKey: Send + Sync {
    /// Method for signing a message
    fn sign(&self, data: &[u8], signature_out: &mut [u8]);
    /// Length of `sign`'s output
    fn signature_len(&self) -> usize;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// A pseudo random key for HKDF
pub trait HandshakeTokenKey: Send + Sync {
    /// Derive AEAD using hkdf
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey>;
}

/// A key for sealing data with AEAD-based algorithms
pub trait AeadKey {
    /// Method for sealing message `data`
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError>;
    /// Method for opening a sealed message `data`
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError>;
}

/// Generic crypto errors
#[derive(Debug)]
pub struct CryptoError;

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub struct UnsupportedVersion;

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
