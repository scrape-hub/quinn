//! Crypto sessions that finish part of the handshake asynchronously
//!
//! See [`crypto::Session::poll_handshake`] and [`Connection::poll_handshake`].

use super::*;

impl Connection {
    /// Let the crypto session continue a handshake that waited for asynchronous work
    ///
    /// A [`crypto::Session`] may do part of the handshake asynchronously, e.g. verify the peer's
    /// certificate on another thread (see [`crypto::Session::poll_handshake()`]). It wakes `waker`
    /// once it can continue. Whoever drives the connection has to call this method then, followed
    /// by `poll_transmit`, so that the handshake messages that became available (e.g. a client's
    /// Finished) are sent at once rather than after the next packet from the peer. `quinn` calls it
    /// whenever it polls a connection's driver. The call is cheap, and it does nothing once the
    /// handshake is complete or for sessions that never wait.
    ///
    /// Returns whether the handshake made progress.
    pub fn poll_handshake(&mut self, now: Instant, waker: &Waker) -> bool {
        if !self.state.is_handshake() {
            return false;
        }
        if !self
            .handshake_waker
            .as_ref()
            .is_some_and(|w| w.will_wake(waker))
        {
            self.handshake_waker = Some(waker.clone());
        }
        let was_pending = self.handshake_pending;
        let result = match self.poll_crypto_session() {
            Poll::Pending => return false,
            Poll::Ready(result) => result,
        };
        // The session may also have finished its work while a packet was processed, which then
        // picked up its results; the handshake is complete once the session says so
        let progressed = was_pending || !self.crypto.is_handshaking();
        let result = match progressed {
            true => result.and_then(|()| self.on_handshake_progress(now)),
            false => result,
        };
        if let Err(err) = result {
            self.fail_handshake(now, err);
            return true;
        }
        self.process_undecryptable();
        progressed
    }

    /// Process the kept 1-RTT packets whose processing was deferred
    pub(super) fn process_deferred_undecryptable(&mut self) {
        if mem::take(&mut self.defer_undecryptable) {
            self.timers.stop(Timer::ProcessUndecryptable);
            self.process_undecryptable();
        }
    }

    /// Poll the crypto session for asynchronous handshake work, keeping track of whether it waits
    pub(super) fn poll_crypto_session(&mut self) -> Poll<Result<(), TransportError>> {
        let result = match &self.handshake_waker {
            Some(waker) => self.crypto.poll_handshake(waker),
            None => self.crypto.poll_handshake(&noop_waker()),
        };
        self.handshake_pending = result.is_pending();
        result
    }

    /// Continue the handshake after the crypto session finished asynchronous work
    pub(super) fn on_handshake_progress(&mut self, now: Instant) -> Result<(), TransportError> {
        let starting_space = self.highest_space;
        self.check_handshake_data();
        self.write_crypto();
        if self.side.is_server()
            && starting_space == SpaceId::Initial
            && self.highest_space != SpaceId::Initial
        {
            self.handle_client_params(now)?;
        }
        if !self.crypto.is_handshaking() {
            self.complete_handshake(now)?;
        }
        Ok(())
    }

    /// Emit `Event::HandshakeDataReady` if asynchronous work of the crypto session produced the
    /// handshake data
    pub(super) fn check_handshake_data(&mut self) {
        if !self.handshake_data_ready && self.crypto.handshake_data().is_some() {
            self.handshake_data_ready = true;
            self.events.push_back(Event::HandshakeDataReady);
        }
    }

    /// Close the connection because the handshake failed outside of packet processing
    pub(super) fn fail_handshake(&mut self, now: Instant, err: TransportError) {
        if self.state.is_closed() {
            return;
        }
        debug!("closing connection due to transport error: {}", err);
        self.error = Some(err.clone().into());
        self.state = State::closed(err);
        self.close_common();
        self.set_close_timer(now);
        self.close = true;
    }

    /// Process the 1-RTT packets that could not be decrypted while the handshake waited
    pub(super) fn process_undecryptable(&mut self) {
        if self.state.is_handshake() || self.undecryptable.is_empty() || self.defer_undecryptable {
            return;
        }
        if self.state.is_closed() {
            self.undecryptable.clear();
            return;
        }
        for (received, remote, ecn, packet) in mem::take(&mut self.undecryptable) {
            trace!("processing 1-RTT packet that arrived during the handshake");
            self.handle_decode(received, remote, ecn, packet);
        }
    }

    /// Number of 1-RTT packets kept during the handshake and not yet processed
    #[cfg(test)]
    pub(crate) fn kept_1rtt_packets(&self) -> usize {
        self.undecryptable.len()
    }
}

/// Number of 1-RTT packets kept while the handshake waits for asynchronous work, as many as
/// quiche keeps (`kDefaultMaxUndecryptablePackets`)
pub(super) const MAX_UNDECRYPTABLE_PACKETS: usize = 10;

/// Longest time [`BufferedPacketProcessing::AfterFirst1rttData`] defers kept 1-RTT packets
pub(super) const MAX_UNDECRYPTABLE_DEFERRAL: Duration = Duration::from_millis(5);

/// A waker for polling crypto sessions outside of a task, e.g. while processing a packet
pub(super) fn noop_waker() -> Waker {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    static WAKER: OnceLock<Waker> = OnceLock::new();
    WAKER.get_or_init(|| Waker::from(Arc::new(Noop))).clone()
}
