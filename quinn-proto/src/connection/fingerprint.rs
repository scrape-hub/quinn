//! Connection helpers behind the fingerprint options: packet padding and coalescing,
//! acknowledgement timing and queuing, and how a connection's Initial keys and close are
//! handled, so the wire matches another QUIC stack's behaviour.
//!
//! See [`FingerprintConfig`](crate::FingerprintConfig).

use super::*;

impl Connection {
    /// Latest time by which the pending acknowledgements have to be sent, if any are pending
    ///
    /// For drivers that defer transmission for a moment, such as quinn's transmit hold: they may
    /// hold back an acknowledgement that is due so that it goes out together with the data being
    /// written, as browsers bundle it into the packet they are building, but not beyond this
    /// time. RFC 9000, section 13.2.1 allows 0-RTT and 1-RTT packets to be acknowledged up to
    /// `max_ack_delay` after their arrival, and requires Initial and Handshake packets to be
    /// acknowledged immediately, which counts as within the timer granularity of 1 ms here (the
    /// delay quiche applies to them). The time counts from the first ack-eliciting packet that
    /// no ACK frame has covered yet.
    pub fn ack_deadline(&self) -> Option<Instant> {
        SpaceId::iter()
            .filter(|&id| self.spaces[id].crypto.is_some())
            .filter_map(|id| {
                let since = self.spaces[id].pending_acks.unacked_since()?;
                Some(match id {
                    SpaceId::Data => since + self.ack_frequency.max_ack_delay,
                    _ => since + TIMER_GRANULARITY,
                })
            })
            .min()
    }

    /// Pad a client datagram that carries an Initial packet to the fixed Initial size
    ///
    /// `builder` holds the last packet of the datagram. Returns whether zero bytes have to be
    /// appended after that packet instead, see [`Self::append_zeros`].
    pub(super) fn pad_initial(&self, builder: &mut PacketBuilder) -> bool {
        let padding = self.config.fingerprint.effective_initial_padding();
        let size = padding.fixed_size().unwrap_or(MIN_INITIAL_SIZE);
        match padding {
            InitialPadding::TrailingZeros { .. }
                if !(builder.short_header && builder.ack_eliciting) =>
            {
                true
            }
            _ => {
                builder.pad_to(size);
                false
            }
        }
    }

    /// Hold back the Finished after a handshake that completed while a packet was processed, see
    /// [`FingerprintConfig::finished_with_first_data`](crate::FingerprintConfig::finished_with_first_data)
    pub(super) fn hold_finished(&mut self, now: Instant) {
        /// Longest time the Finished waits for the application
        const MAX_FINISHED_HOLD: Duration = Duration::from_millis(2);
        /// How long the Finished waits if the acknowledgements of the server's flight are overdue
        /// already, e.g. because the flight arrived in parts: quiche writes the control stream at
        /// once regardless of its timers, and applications write it within a fraction of this
        const LATE_FINISHED_HOLD: Duration = Duration::from_micros(500);
        // With 0-RTT, the application could write before the handshake completed
        if !self.side.is_client()
            || !self.config.fingerprint.finished_with_first_data
            || self.zero_rtt_enabled
        {
            return;
        }
        let deadline = match self.ack_deadline() {
            Some(ack) if ack > now => ack.min(now + MAX_FINISHED_HOLD),
            Some(_) => now + LATE_FINISHED_HOLD,
            None => now + MAX_FINISHED_HOLD,
        };
        trace!("holding the Finished for the first application data");
        self.finished_held = true;
        self.timers.set(Timer::FinishedHold, deadline);
    }

    /// Whether the Finished held by [`Self::hold_finished`] goes out now: stream data is queued or
    /// the hold's deadline has passed
    pub(super) fn finished_hold_over(&self, now: Instant) -> bool {
        self.streams.can_send_stream_data() || self.timers.is_expired(Timer::FinishedHold, now)
    }

    pub(super) fn release_finished(&mut self) {
        self.finished_held = false;
        self.timers.stop(Timer::FinishedHold);
    }

    /// Keep an unfinished Initial packet until the packets coalesced after it are written, if the
    /// padding style asks for it
    ///
    /// quiche pads a datagram that carries an Initial packet with PADDING frames inside the
    /// Initial packet, however many packets follow it: its coalescer serializes the Initial packet
    /// again with the padding once the datagram is complete (`QuicConnection::
    /// FlushCoalescedPacket`, `QuicPacketCreator::SerializeCoalescedPacket`).
    /// [`InitialPadding::Frames`] does the same, so the Initial packet is finished last, by
    /// [`Self::finish_held_initial`]. Returns `builder` if it is not held.
    pub(super) fn hold_initial(
        &self,
        builder: PacketBuilder,
        sent: &mut Option<SentFrames>,
        buf: &[u8],
    ) -> Result<HeldInitial, PacketBuilder> {
        let frames = matches!(
            self.config.fingerprint.effective_initial_padding(),
            InitialPadding::Frames { .. }
        );
        if builder.space != SpaceId::Initial || !frames {
            return Err(builder);
        }
        Ok(HeldInitial {
            builder,
            sent: sent.take(),
            end: buf.len(),
            #[cfg(test)]
            log_position: self.sent_log.as_ref().map_or(0, |log| log.len()),
        })
    }

    /// Finish an Initial packet kept by [`Self::hold_initial`] now that the packets after it in
    /// the datagram are written: pad it so that the datagram has the fixed Initial size, encrypt
    /// it and put the other packets back behind it
    ///
    /// Returns the room the Initial packet's authentication tag had reserved.
    pub(super) fn finish_held_initial(
        &mut self,
        now: Instant,
        held: HeldInitial,
        buf: &mut Vec<u8>,
        initial_size: Option<u16>,
    ) -> usize {
        let HeldInitial {
            mut builder,
            sent,
            end,
            ..
        } = held;
        let tag_len = builder.tag_len;
        let rest = buf.split_off(end);
        let size = initial_size.unwrap_or(MIN_INITIAL_SIZE);
        builder.pad_to(size.saturating_sub(rest.len() as u16));
        builder.finish_and_track(now, self, sent, buf);
        buf.extend_from_slice(&rest);
        #[cfg(test)]
        if let Some(log) = &mut self.sent_log {
            // In the order of the datagram
            let entry = log.pop().unwrap();
            log.insert(held.log_position, entry);
        }
        tag_len
    }

    /// The transition out of a held Initial packet, at the end of a datagram or of the packets
    /// `poll_transmit` writes: finishes it via [`Self::finish_held_initial`] if one is held, then
    /// discards the Initial keys if `discard_initial` says so. Returns the room the Initial
    /// packet's authentication tag had reserved, 0 if none was held.
    pub(super) fn conclude_held_initial(
        &mut self,
        now: Instant,
        held_initial: &mut Option<HeldInitial>,
        discard_initial: &mut bool,
        buf: &mut Vec<u8>,
        initial_size: Option<u16>,
    ) -> usize {
        let tag_len = match held_initial.take() {
            Some(held) => self.finish_held_initial(now, held, buf, initial_size),
            None => 0,
        };
        if mem::take(discard_initial) {
            self.discard_space(now, SpaceId::Initial);
        }
        tag_len
    }

    /// Extend the datagram starting at `datagram_start` with zero bytes to the fixed Initial size
    pub(super) fn append_zeros(
        buf: &mut Vec<u8>,
        datagram_start: usize,
        initial_size: Option<u16>,
    ) {
        let end = datagram_start + usize::from(initial_size.unwrap_or(MIN_INITIAL_SIZE));
        if buf.len() < end {
            trace!("{} trailing zero bytes", end - buf.len());
            buf.resize(end, 0);
        }
    }

    /// Close a connection immediately with a transport-level `CONNECTION_CLOSE` frame (type
    /// `0x1c`) instead of an application-level one
    ///
    /// Browsers close connections they no longer need this way, e.g. Chrome with error code
    /// `NO_ERROR`, frame type 0 and the reason `"70:net error"`. `frame_type` is the type of the
    /// frame that triggered the error; `None` is encoded as 0. Otherwise this behaves like
    /// [`close()`](Self::close).
    pub fn close_transport(
        &mut self,
        now: Instant,
        error_code: TransportErrorCode,
        frame_type: Option<VarInt>,
        reason: Bytes,
    ) {
        self.close_inner(
            now,
            Close::Connection(frame::ConnectionClose {
                error_code,
                frame_type: frame_type.map(frame::FrameType::from_varint),
                reason,
            }),
        )
    }

    /// Discard the connection without sending anything to the peer
    ///
    /// Chromium drops QUIC sessions it no longer needs this way. Unlike [`close()`](Self::close),
    /// no `CONNECTION_CLOSE` frame is sent, and nothing else either: the connection is drained at
    /// once, so [`poll_transmit()`](Self::poll_transmit) returns `None` from now on, all timers
    /// stop, and the endpoint forgets the connection when it handles the
    /// [`EndpointEvent`] that [`poll_endpoint_events()`] yields. Data not
    /// yet sent or acknowledged is lost, and [`poll()`](Self::poll) reports
    /// [`ConnectionError::LocallyClosed`]. The peer notices only when its idle timeout expires;
    /// packets it sends meanwhile reach an endpoint that no longer knows the connection, which
    /// answers those addressed to a non-empty connection ID with a stateless reset.
    ///
    /// Does nothing if the connection is drained already.
    ///
    /// [`poll_endpoint_events()`]: Self::poll_endpoint_events
    pub fn abandon(&mut self) {
        if self.state.is_drained() {
            return;
        }
        trace!("abandoning connection");
        self.kill(ConnectionError::LocallyClosed);
    }

    /// Arm the timer for acknowledgements of Initial and Handshake packets that are delayed by
    /// [`AckPolicy::Quiche`]
    pub(super) fn set_handshake_ack_timer(&mut self) {
        let deadline = [SpaceId::Initial, SpaceId::Handshake]
            .into_iter()
            .map(|space| &self.spaces[space])
            .filter(|space| space.crypto.is_some() && !space.pending_acks.current_ack_due())
            .filter_map(|space| space.pending_acks.max_ack_delay_timeout(TIMER_GRANULARITY))
            .min();
        match deadline {
            Some(deadline) => self.timers.set(Timer::HandshakeAckDelay, deadline),
            None => self.timers.stop(Timer::HandshakeAckDelay),
        }
    }

    /// Write an ACK frame kept by [`PendingAcks::queue_due_ack`](spaces::PendingAcks::queue_due_ack)
    pub(super) fn populate_queued_ack(
        now: Instant,
        receiving_ecn: bool,
        sent: &mut SentFrames,
        queued: QueuedAck,
        buf: &mut Vec<u8>,
        stats: &mut ConnectionStats,
    ) {
        let ecn = receiving_ecn.then_some(&queued.ecn);
        sent.largest_acked = queued.ranges.max();
        let delay_micros = queued
            .largest_received
            .map_or(0, |received| (now - received).as_micros() as u64);
        let delay = delay_micros >> crate::transport_parameters::DEFAULT_ACK_DELAY_EXPONENT;
        trace!("ACK {:?}, Delay = {}us (kept)", queued.ranges, delay_micros);
        frame::Ack::encode(delay as _, &queued.ranges, ecn, buf);
        stats.frame_tx.acks += 1;
    }

    /// Whether the next packet of `space_id`, which would only carry acknowledgements, needs an
    /// ack-eliciting frame, as [`AckPolicy::Quiche`] adds one after 19 such packets
    pub(super) fn needs_ack_eliciting_frame(
        &self,
        space_id: SpaceId,
        can_send: SendableFrames,
    ) -> bool {
        /// quiche's `kMaxConsecutiveNonRetransmittablePackets`
        const MAX_CONSECUTIVE_NON_ACK_ELICITING: u64 = 19;
        self.config.fingerprint.ack_policy == AckPolicy::Quiche
            && space_id == SpaceId::Data
            && self.spaces[space_id].crypto.is_some()
            && can_send.acks
            && self.non_ack_eliciting_run >= MAX_CONSECUTIVE_NON_ACK_ELICITING
    }

    /// Number of connection IDs the endpoint should issue to a new client connection before it
    /// is used, see [`FingerprintConfig::early_connection_ids`](crate::FingerprintConfig)
    pub(crate) fn early_cids_wanted(&self) -> u64 {
        self.early_cids
    }

    /// Packet number of the next packet in the application data space
    pub(super) fn peek_data_pn(&self) -> u64 {
        match self.shared_pn {
            Some(pn) => pn,
            None => self.packet_number_filter.peek(&self.spaces[SpaceId::Data]),
        }
    }

    #[cfg(test)]
    pub(crate) fn shared_packet_number(&self) -> Option<u64> {
        self.shared_pn
    }

    #[cfg(test)]
    pub(crate) fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// Record every packet sent from now on, see [`Self::sent_log`]
    #[cfg(test)]
    pub(crate) fn log_sent_packets(&mut self) {
        self.sent_log.get_or_insert_with(Vec::new);
    }

    /// The packets sent since [`Self::log_sent_packets`], before encryption
    #[cfg(test)]
    pub(crate) fn sent_log(&self) -> &[SentPacketLog] {
        self.sent_log
            .as_deref()
            .expect("sent packets are not being logged")
    }

    /// Forget the packets logged so far
    #[cfg(test)]
    pub(crate) fn clear_sent_log(&mut self) {
        if let Some(log) = &mut self.sent_log {
            log.clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn logs_sent_packets(&self) -> bool {
        self.sent_log.is_some()
    }

    #[cfg(test)]
    pub(crate) fn log_sent_packet(&mut self, packet: SentPacketLog) {
        if let Some(log) = &mut self.sent_log {
            log.push(packet);
        }
    }

    #[cfg(test)]
    pub(crate) fn remote_cid_capacity(&self) -> usize {
        self.rem_cids.capacity()
    }

    #[cfg(test)]
    pub(crate) fn ack_eliciting_threshold(&self) -> u64 {
        self.spaces[SpaceId::Data]
            .pending_acks
            .ack_eliciting_threshold()
    }
}

/// An Initial packet whose padding and encryption wait for the rest of its datagram
pub(super) struct HeldInitial {
    builder: PacketBuilder,
    sent: Option<SentFrames>,
    /// End of its frames in the datagram buffer
    end: usize,
    /// Its position in the log of sent packets
    #[cfg(test)]
    log_position: usize,
}

impl HeldInitial {
    pub(super) fn tag_len(&self) -> usize {
        self.builder.tag_len
    }
}

/// A packet as it was sent, before encryption
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct SentPacketLog {
    pub(crate) time: Instant,
    pub(crate) space: SpaceId,
    pub(crate) zero_rtt: bool,
    pub(crate) number: u64,
    /// Length of the encrypted packet
    pub(crate) len: usize,
    /// Frames and padding
    pub(crate) payload: Bytes,
}
