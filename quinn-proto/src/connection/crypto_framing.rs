//! Framings of client Initial CRYPTO data used by other QUIC implementations
//!
//! See [`CryptoFraming`] for what they look like on the wire.

// Parts of this file are translated from other QUIC implementations (see THIRD-PARTY-NOTICES):
//
// - `chaos_layout`, `multi_packet_split` and `chaos_protect` follow `QuicChaosProtector`
//   (quiche/quic/core/quic_chaos_protector.cc) and `QuicPacketCreator::MultiPacketChaosProtect`
//   and `ConsumeCryptoDataToFillCurrentPacket` (quiche/quic/core/quic_packet_creator.cc) of
//   QUICHE, https://github.com/google/quiche, commit 2c4a124642f095f995cd2e9e2fe10decc08df662.
//   Copyright (c) 2021 The Chromium Authors. All rights reserved.
//   Copyright (c) 2012 The Chromium Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style license (BSD-3-Clause) that can be found
//   in licenses/quiche-LICENSE.
//
// - `find_sni`, `slice_sni` and `limit_chunks` follow neqo-transport/src/sni.rs and
//   `CryptoStreams::write_frame` in neqo-transport/src/crypto.rs of neqo,
//   https://github.com/mozilla/neqo, v0.30.1.
//   Copyright (c) 2019 Mozilla Foundation.
//   Licensed under the Apache License, Version 2.0 (licenses/neqo-LICENSE-APACHE) or the MIT
//   license (licenses/neqo-LICENSE-MIT), at your option.

use std::ops::Range;

use bytes::Bytes;
use rand::RngCore;
use tracing::trace;

use super::{SentFrames, spaces::PacketSpace, stats::FrameStats};
use crate::{CryptoFraming, VarInt, coding::BufMutExt, frame};

/// What the caller has to do after [`write_initial_crypto`]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Outcome {
    /// The datagram must end after this packet
    pub(super) end_datagram: bool,
    /// The next packet gets a packet number of at least two bytes
    pub(super) widen_next_pn: bool,
}

/// Where a packet is located in the datagram buffer
#[derive(Debug, Clone, Copy)]
pub(super) struct PacketBounds {
    /// Position of the enclosing datagram
    pub(super) datagram_start: usize,
    /// Position of the first frame of the packet
    pub(super) payload_start: usize,
    /// Largest position frames may occupy
    pub(super) max_size: usize,
}

/// Write CRYPTO data of a client Initial packet according to `framing`
///
/// `buf` holds the packet so far, which may already contain frames. Writes nothing if `framing`
/// does not apply to the pending data, in which case the caller writes it in order.
pub(super) fn write_initial_crypto(
    framing: CryptoFraming,
    space: &mut PacketSpace,
    buf: &mut Vec<u8>,
    bounds: PacketBounds,
    rng: &mut dyn RngCore,
    sent: &mut SentFrames,
    stats: &mut FrameStats,
) -> Outcome {
    let max_size = bounds.max_size;
    match framing {
        CryptoFraming::InOrder => Outcome::default(),
        CryptoFraming::ChaosProtection => {
            chaos_protect(space, buf, max_size, bounds.payload_start, rng, sent, stats)
        }
        CryptoFraming::SniSlicing => Outcome {
            end_datagram: slice_sni(
                space,
                buf,
                max_size,
                max_size - bounds.datagram_start,
                sent,
                stats,
            ),
            widen_next_pn: false,
        },
        CryptoFraming::Chunked { max } => Outcome {
            end_datagram: write_chunk(space, buf, max_size, usize::from(max), sent, stats),
            widen_next_pn: false,
        },
    }
}

/// Apple's framing: one CRYPTO frame with at most `max` bytes of the pending data, in order;
/// `false` if there is none to write
fn write_chunk(
    space: &mut PacketSpace,
    buf: &mut Vec<u8>,
    max_size: usize,
    max: usize,
    sent: &mut SentFrames,
    stats: &mut FrameStats,
) -> bool {
    let Some(pending) = space.pending.crypto.pop_front() else {
        return false;
    };
    let offset = pending.offset;
    let room = max_size.saturating_sub(buf.len());
    let len = pending.data.len().min(max);
    let len = len.min(room.saturating_sub(crypto_header_len(offset, len as u64)));
    if len == 0 {
        space.pending.crypto.push_front(pending);
        return false;
    }
    if len < pending.data.len() {
        space.pending.crypto.push_front(frame::Crypto {
            offset: offset + len as u64,
            data: pending.data.slice(len..),
        });
    }
    let frame = frame::Crypto {
        offset,
        data: pending.data.slice(..len),
    };
    write_crypto_frame(frame, buf, sent, stats);
    true
}

fn write_crypto_frame(
    frame: frame::Crypto,
    buf: &mut Vec<u8>,
    sent: &mut SentFrames,
    stats: &mut FrameStats,
) {
    trace!("CRYPTO: off {} len {}", frame.offset, frame.data.len());
    frame.encode(buf);
    stats.crypto += 1;
    sent.retransmits.get_or_create().crypto.push_back(frame);
}

/// Encoded size of a CRYPTO frame header, as quiche's `GetMinCryptoFrameSize`
fn crypto_header_len(offset: u64, len: u64) -> usize {
    1 + VarInt(offset).size() + VarInt(len).size()
}

/// A frame of a chaos-protected packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChaosFrame {
    /// Frames written before the CRYPTO data, e.g. an ACK; never moved and never preceded by
    /// padding, like quiche treats ACK frames
    Prefix,
    /// A CRYPTO frame covering `len` bytes at `offset`
    Crypto { offset: u64, len: u64 },
    /// A PING frame
    Ping,
    /// `n` bytes of PADDING
    Padding(usize),
}

/// quiche's `QuicPacketCreator::MultiPacketChaosProtect` decision for a ClientHello of `len`
/// bytes and `bytes_free` bytes of room in the first packet
///
/// Returns the lengths of the first and last chunk to send in the first packet, or `None` if the
/// data is sent in order. `first_chunk_random` is a random number that picks the first chunk's
/// length.
pub(super) fn multi_packet_split(
    len: u64,
    bytes_free: u64,
    first_chunk_random: u64,
) -> Option<(u64, u64)> {
    let min_frame = crypto_header_len(len - 1, len) as u64;
    if bytes_free < 2 * min_frame {
        return None;
    }
    let first_packet = bytes_free - 2 * min_frame;
    // All packets share the current header size, so later packets have the room of the first
    // one minus one CRYPTO frame header
    let other_packets = bytes_free - min_frame;
    if len <= first_packet {
        return None;
    }
    let occupied = other_packets - first_packet;
    let packets = (len + occupied).div_ceil(other_packets);
    let data_in_other_packets = (len + occupied).div_ceil(packets);
    if data_in_other_packets < occupied {
        return None;
    }
    let data_in_first_packet = data_in_other_packets - occupied;
    // The ClientHello header and the length of the first extension, plus some randomness
    const MIN_FIRST_FRAME_LENGTH: u64 = 55;
    const FIRST_FRAME_LENGTH_RANDOM: u64 = 32;
    let first = MIN_FIRST_FRAME_LENGTH + first_chunk_random % FIRST_FRAME_LENGTH_RANDOM;
    if len <= first || data_in_first_packet <= first {
        return None;
    }
    Some((first, data_in_first_packet - first))
}

/// quiche's `QuicChaosProtector`: split the CRYPTO frames of a packet, add PING frames, spread
/// `padding` bytes of PADDING between them and shuffle everything except the prefix
pub(super) fn chaos_layout(
    mut frames: Vec<ChaosFrame>,
    mut padding: usize,
    rng: &mut dyn RngCore,
) -> Vec<ChaosFrame> {
    // quiche draws both the number of crypto-frame splits and the number of PING frames
    // uniformly from this same range.
    const MIN_CHAOS_COUNT: u64 = 2;
    const MAX_CHAOS_COUNT: u64 = 10;

    let mut rand = |n: u64| rng.next_u64() % n;

    // SplitCryptoFrame
    let (start, end) = frames
        .iter()
        .filter_map(|f| match *f {
            ChaosFrame::Crypto { offset, len } => Some((offset, offset + len)),
            _ => None,
        })
        .fold((u64::MAX, 0), |(s, e), (a, b)| (s.min(a), e.max(b)));
    if start < end {
        let max_overhead = crypto_header_len(end, end - start);
        let splits = MIN_CHAOS_COUNT + rand(MAX_CHAOS_COUNT + 1 - MIN_CHAOS_COUNT);
        for _ in 0..splits {
            if padding < max_overhead {
                break;
            }
            let index = rand(frames.len() as u64) as usize;
            let ChaosFrame::Crypto { offset, len } = frames[index] else {
                continue;
            };
            if len <= 1 {
                continue;
            }
            let old_overhead = crypto_header_len(offset, len);
            let first_len = 1 + rand(len - 1);
            let new_offset = offset + first_len;
            let new_len = len - first_len;
            frames[index] = ChaosFrame::Crypto {
                offset,
                len: first_len,
            };
            frames.push(ChaosFrame::Crypto {
                offset: new_offset,
                len: new_len,
            });
            padding = padding + old_overhead
                - crypto_header_len(new_offset, new_len)
                - crypto_header_len(offset, first_len);
        }
    }

    // AddPingFrames
    if padding != 0 {
        let pings = (MIN_CHAOS_COUNT + rand(MAX_CHAOS_COUNT + 1 - MIN_CHAOS_COUNT))
            .min(padding as u64) as usize;
        frames.extend(std::iter::repeat(ChaosFrame::Ping).take(pings));
        padding -= pings;
    }

    // SpreadPadding
    let mut i = 0;
    while i < frames.len() {
        let n = rand(padding as u64 + 1) as usize;
        if n > 0 && frames[i] != ChaosFrame::Prefix {
            frames.insert(i, ChaosFrame::Padding(n));
            i += 1;
            padding -= n;
        }
        i += 1;
    }
    if padding > 0 {
        frames.push(ChaosFrame::Padding(padding));
    }

    // ReorderFrames
    for i in (1..frames.len()).rev() {
        let j = rand(i as u64 + 1) as usize;
        if frames[i] != ChaosFrame::Prefix && frames[j] != ChaosFrame::Prefix {
            frames.swap(i, j);
        }
    }
    frames
}

/// Fill the rest of a client Initial packet the way quiche does with chaos protection enabled
///
/// Frames written after `payload_start` are kept in front of the CRYPTO data.
fn chaos_protect(
    space: &mut PacketSpace,
    buf: &mut Vec<u8>,
    max_size: usize,
    payload_start: usize,
    rng: &mut dyn RngCore,
    sent: &mut SentFrames,
    stats: &mut FrameStats,
) -> Outcome {
    let mut outcome = Outcome::default();
    let bytes_free = max_size.saturating_sub(buf.len());
    // (offset, data) of every CRYPTO chunk placed in this packet
    let mut chunks = Vec::<(u64, Bytes)>::new();
    let mut used = 0;

    let multi = match space.pending.crypto.front() {
        Some(front) if front.offset == 0 => {
            let random = rng.next_u64();
            multi_packet_split(front.data.len() as u64, bytes_free as u64, random)
        }
        _ => None,
    };

    if let Some((first, last)) = multi {
        // The start and the end of the ClientHello; the middle follows in later packets.
        // `front()` above already confirmed the deque is non-empty, and nothing between there
        // and here can remove its front entry.
        let front = space.pending.crypto.pop_front().unwrap();
        let len = front.data.len() as u64;
        chunks.push((0, front.data.slice(..first as usize)));
        chunks.push((len - last, front.data.slice((len - last) as usize..)));
        used += crypto_header_len(0, first) + first as usize;
        used += crypto_header_len(len - last, last) + last as usize;
        space.pending.crypto.push_front(frame::Crypto {
            offset: first,
            data: front.data.slice(first as usize..(len - last) as usize),
        });
        // quiche estimates the packet number length of the next packet while this packet waits
        // unpadded in its coalescer, which yields two bytes
        outcome.widen_next_pn = true;
        trace!(first, last, "multi-packet chaos protection");
    } else {
        // Fill the packet as quiche's `ConsumeCryptoDataToFillCurrentPacket` does
        while let Some(front) = space.pending.crypto.front_mut() {
            let remaining = front.data.len() as u64;
            let header = crypto_header_len(front.offset, remaining);
            if bytes_free <= used + header {
                break;
            }
            let len = remaining.min((bytes_free - used - header) as u64);
            let offset = front.offset;
            let data = front.data.split_to(len as usize);
            front.offset += len;
            if front.data.is_empty() {
                space.pending.crypto.pop_front();
            }
            used += crypto_header_len(offset, len) + len as usize;
            chunks.push((offset, data));
        }
    }

    if chunks.is_empty() {
        return outcome;
    }

    let mut layout = Vec::with_capacity(chunks.len() + 1);
    if buf.len() > payload_start {
        layout.push(ChaosFrame::Prefix);
    }
    layout.extend(chunks.iter().map(|(offset, data)| ChaosFrame::Crypto {
        offset: *offset,
        len: data.len() as u64,
    }));
    let padding = bytes_free - used;
    if padding > 0 {
        // quiche only applies chaos protection to packets that have room for padding
        layout = chaos_layout(layout, padding, rng);
    }

    for f in layout {
        match f {
            ChaosFrame::Prefix => {}
            ChaosFrame::Crypto { offset, len } => {
                let (base, data) = chunks
                    .iter()
                    .find(|(o, d)| *o <= offset && offset + len <= *o + d.len() as u64)
                    .expect("chaos frames stay within their chunks");
                let start = (offset - base) as usize;
                let frame = frame::Crypto {
                    offset,
                    data: data.slice(start..start + len as usize),
                };
                write_crypto_frame(frame, buf, sent, stats);
            }
            ChaosFrame::Ping => {
                trace!("PING");
                buf.write(frame::FrameType::PING);
                stats.ping += 1;
            }
            ChaosFrame::Padding(n) => buf.resize(buf.len() + n, 0),
        }
    }
    debug_assert_eq!(buf.len(), max_size, "chaos-protected packets are full");
    outcome
}

/// neqo's SNI slicing of CRYPTO data starting at offset 0
///
/// `limit` is the room for the whole packet, header included. Returns whether the data was
/// sliced; if not, nothing was written.
fn slice_sni(
    space: &mut PacketSpace,
    buf: &mut Vec<u8>,
    max_size: usize,
    limit: usize,
    sent: &mut SentFrames,
    stats: &mut FrameStats,
) -> bool {
    let Some(front) = space.pending.crypto.front() else {
        return false;
    };
    if front.offset != 0 {
        return false;
    }
    let Some(sni) = find_sni(&front.data) else {
        return false;
    };
    // `front()` above already confirmed the deque is non-empty, and nothing between there and
    // here can remove its front entry.
    let data = space.pending.crypto.pop_front().unwrap().data;
    let len = data.len();

    // Cut the crypto data in two at the midpoint of the SNI and swap the chunks
    let mid = sni.start + (sni.end - sni.start) / 2;
    // Truncate the chunks so they fit into roughly evenly-filled packets
    let packets_needed = len.div_ceil(limit.max(1));
    let chunk_limit = len / packets_needed;
    let (left, right) = limit_chunks(0..mid, mid..len, chunk_limit);

    let mut written = Vec::new();
    for range in [right, left] {
        let remaining = max_size.saturating_sub(buf.len());
        let offset = range.start as u64;
        // Header with a one-byte length first, to avoid underestimating the room for data.
        // `offset` and the `n` below come from the length of the CRYPTO data (a ClientHello),
        // always far below VarInt's 62-bit range.
        let mut header = 1 + VarInt::size(VarInt::from_u64(offset).unwrap()) + 1;
        if remaining < header + 1 {
            continue;
        }
        let n = range.len().min(remaining - header);
        header += VarInt::size(VarInt::from_u64(n as u64).unwrap()) - 1;
        let n = range.len().min(remaining - header);
        if n == 0 {
            continue;
        }
        let frame = frame::Crypto {
            offset,
            data: data.slice(range.start..range.start + n),
        };
        write_crypto_frame(frame, buf, sent, stats);
        written.push(range.start..range.start + n);
    }
    trace!(?sni, ?written, "SNI slicing");

    // Queue everything that was not written, in order
    let mut unsent = Vec::new();
    let mut pos = 0;
    written.sort_by_key(|r| r.start);
    for range in written {
        if pos < range.start {
            unsent.push(pos..range.start);
        }
        pos = pos.max(range.end);
    }
    if pos < len {
        unsent.push(pos..len);
    }
    for range in unsent.into_iter().rev() {
        space.pending.crypto.push_front(frame::Crypto {
            offset: range.start as u64,
            data: data.slice(range),
        });
    }
    true
}

/// neqo's `limit_chunks`: shorten the chunks before and after the cut to `limit` bytes together
fn limit_chunks(
    left: Range<usize>,
    right: Range<usize>,
    limit: usize,
) -> (Range<usize>, Range<usize>) {
    if left.len() + right.len() <= limit {
        // Both fit, so the SNI is not spread over packets, but it is in two unordered frames
        (left, right)
    } else if left.len() <= limit {
        // Send the end of `right`, so that the second half of the SNI is in another packet
        let skip = right.len() + left.len() - limit;
        (left, right.start + skip..right.end)
    } else if right.len() <= limit {
        // Send only the start of `left`; the first half of the SNI goes into another packet
        (left.start..left.start + limit - right.len(), right)
    } else {
        // Both are too long, send a part of each
        (
            left.start..left.start + limit / 2,
            right.start..right.start + limit / 2,
        )
    }
}

/// Position of the server name in a ClientHello, as neqo's `find_sni` determines it
pub(super) fn find_sni(buf: &[u8]) -> Option<Range<usize>> {
    struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }
    impl Reader<'_> {
        fn skip(&mut self, n: usize) -> Option<()> {
            (self.buf.len() - self.pos >= n).then(|| self.pos += n)
        }
        fn uint(&mut self, n: usize) -> Option<usize> {
            let bytes = self.buf.get(self.pos..self.pos + n)?;
            self.pos += n;
            Some(bytes.iter().fold(0, |acc, b| acc << 8 | usize::from(*b)))
        }
        fn skip_vec(&mut self, len_size: usize) -> Option<()> {
            let n = self.uint(len_size)?;
            self.skip(n)
        }
    }

    let mut r = Reader { buf, pos: 0 };
    // ClientHello handshake message
    if r.uint(1)? != 1 {
        return None;
    }
    r.skip(3 + 2 + 32)?; // length, version, random
    r.skip_vec(1)?; // session_id
    r.skip_vec(2)?; // cipher_suites
    r.skip_vec(1)?; // compression_methods
    r.skip(2)?; // extensions length
    while buf.len() - r.pos >= 4 {
        let ext_type = r.uint(2)?;
        let ext_len = r.uint(2)?;
        if ext_type == 0 {
            let list_len = r.uint(2)?;
            if list_len < 3 {
                return None;
            }
            r.skip(3)?; // name_type and host_name length
            let start = r.pos;
            let end = start + list_len - 3;
            if end > buf.len() {
                return None;
            }
            return Some(start..end);
        }
        r.skip(ext_len)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::Instant;

    /// A ClientHello with three cipher suites and the given extensions, each `(type, length)`;
    /// extension 0 is a server name extension for `host`
    fn client_hello(extensions: &[(u16, usize)], host: &str) -> Vec<u8> {
        let mut exts = Vec::new();
        for &(ty, len) in extensions {
            exts.extend_from_slice(&ty.to_be_bytes());
            exts.extend_from_slice(&(len as u16).to_be_bytes());
            if ty == 0 {
                assert_eq!(len, host.len() + 5);
                exts.extend_from_slice(&(host.len() as u16 + 3).to_be_bytes());
                exts.push(0);
                exts.extend_from_slice(&(host.len() as u16).to_be_bytes());
                exts.extend_from_slice(host.as_bytes());
            } else {
                exts.extend(std::iter::repeat(0xab).take(len));
            }
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x42; 32]);
        body.push(0); // session_id
        body.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hello = vec![1];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    /// Extension layout of a Firefox 156 ClientHello to www.google.com (1908 bytes)
    const FIREFOX_FULL: &[(u16, usize)] = &[
        (0x0010, 5),
        (0x002d, 2),
        (0x0022, 16),
        (0x001b, 7),
        (0x001c, 2),
        (0x002b, 3),
        (0x0017, 0),
        (0x0005, 5),
        (0x000a, 12),
        (0x000d, 30),
        (0x0000, 19),
        (0xff01, 1),
        (0x0033, 1327),
        (0x0039, 86),
        (0xfe0d, 282),
    ];

    /// Extension layout of a Firefox 156 ClientHello to dl.google.com (1907 bytes)
    const FIREFOX_LATE_SNI: &[(u16, usize)] = &[
        (0x002d, 2),
        (0x0022, 16),
        (0x000a, 12),
        (0x000d, 30),
        (0x001c, 2),
        (0x0005, 5),
        (0x0033, 1327),
        (0x0010, 5),
        (0x0017, 0),
        (0x0000, 18),
        (0x001b, 7),
        (0x002b, 3),
        (0xff01, 1),
        (0x0039, 86),
        (0xfe0d, 282),
    ];

    /// Extension layout of a resumed Firefox 156 ClientHello (2513 bytes)
    const FIREFOX_RESUMED: &[(u16, usize)] = &[
        (0x0010, 5),
        (0x0017, 0),
        (0x001b, 7),
        (0x000d, 30),
        (0x002b, 3),
        (0x002d, 2),
        (0xff01, 1),
        (0x002a, 0),
        (0x0005, 5),
        (0x001c, 2),
        (0x0022, 16),
        (0x0000, 19),
        (0x000a, 12),
        (0x0033, 1327),
        (0x0039, 86),
        (0xfe0d, 570),
        (0x0029, 309),
    ];

    /// Parsed frames of a packet payload: CRYPTO as `(offset, len)`, PING as `(u64::MAX, 0)`,
    /// PADDING runs as `(u64::MAX, n)`
    fn frames(payload: &[u8]) -> Vec<(u64, usize)> {
        let mut out: Vec<(u64, usize)> = Vec::new();
        for frame in frame::Iter::new(Bytes::copy_from_slice(payload)).unwrap() {
            match frame.unwrap() {
                frame::Frame::Crypto(c) => out.push((c.offset, c.data.len())),
                frame::Frame::Ping => out.push((u64::MAX, 0)),
                frame::Frame::Padding => match out.last_mut() {
                    Some((u64::MAX, n)) if *n > 0 => *n += 1,
                    _ => out.push((u64::MAX, 1)),
                },
                f => panic!("unexpected frame {f:?}"),
            }
        }
        out
    }

    fn pending(space: &PacketSpace) -> Vec<(u64, usize)> {
        space
            .pending
            .crypto
            .iter()
            .map(|c| (c.offset, c.data.len()))
            .collect()
    }

    /// Build one packet with `header_len` header bytes in a datagram of `datagram_len` bytes
    fn packet(
        framing: CryptoFraming,
        space: &mut PacketSpace,
        header_len: usize,
        datagram_len: usize,
        rng: &mut StdRng,
    ) -> (Vec<(u64, usize)>, Outcome) {
        let mut buf = vec![0xff; header_len];
        let bounds = PacketBounds {
            datagram_start: 0,
            payload_start: header_len,
            max_size: datagram_len - 16,
        };
        let outcome = write_initial_crypto(
            framing,
            space,
            &mut buf,
            bounds,
            rng,
            &mut SentFrames::default(),
            &mut FrameStats::default(),
        );
        if !outcome.end_datagram {
            // What `Connection::populate_packet` does with the rest of the pending data
            while buf.len() + frame::Crypto::SIZE_BOUND < bounds.max_size {
                let Some(mut frame) = space.pending.crypto.pop_front() else {
                    break;
                };
                let room = bounds.max_size - buf.len() - 1 - VarInt(frame.offset).size() - 2;
                let data = frame.data.split_to(frame.data.len().min(room));
                frame::Crypto {
                    offset: frame.offset,
                    data: data.clone(),
                }
                .encode(&mut buf);
                if !frame.data.is_empty() {
                    frame.offset += data.len() as u64;
                    space.pending.crypto.push_front(frame);
                }
            }
        }
        (frames(&buf[header_len..]), outcome)
    }

    fn queue(space: &mut PacketSpace, hello: Vec<u8>) {
        space.pending.crypto.push_back(frame::Crypto {
            offset: 0,
            data: hello.into(),
        });
    }

    /// Safari's ClientHello: 999 bytes in the first packet, the rest in the second, each packet
    /// ending its datagram
    #[test]
    fn chunked_crypto_data() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut space = PacketSpace::new(Instant::now());
        queue(&mut space, vec![0x16; 1478]);
        let framing = CryptoFraming::Chunked { max: 999 };
        let (first, outcome) = packet(framing, &mut space, 20, 1200, &mut rng);
        assert_eq!(first, [(0, 999)]);
        assert!(outcome.end_datagram);
        let (second, outcome) = packet(framing, &mut space, 20, 1200, &mut rng);
        assert_eq!(second, [(999, 479)]);
        assert!(outcome.end_datagram);
        assert!(pending(&space).is_empty());
        // Without CRYPTO data the packet is left to the caller.
        let mut buf = vec![0xff; 20];
        let bounds = PacketBounds {
            datagram_start: 0,
            payload_start: 20,
            max_size: 1184,
        };
        let outcome = write_initial_crypto(
            framing,
            &mut space,
            &mut buf,
            bounds,
            &mut rng,
            &mut SentFrames::default(),
            &mut FrameStats::default(),
        );
        assert_eq!((buf.len(), outcome), (20, Outcome::default()));
    }

    #[test]
    fn find_server_name() {
        let hello = client_hello(FIREFOX_FULL, "www.google.com");
        assert_eq!(hello.len(), 1908);
        assert_eq!(find_sni(&hello), Some(182..196));
        assert_eq!(&hello[182..196], b"www.google.com");
        let hello = client_hello(&[(0x0010, 5)], "unused");
        assert_eq!(find_sni(&hello), None);
        assert_eq!(find_sni(&hello[..30]), None);
        assert_eq!(find_sni(&[2, 0, 0]), None);
    }

    /// Firefox 156 to www.google.com: Initial pn 321 (2-byte), DCID 8, SCID 3, no token
    #[test]
    fn sni_slicing_matches_capture() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut space = PacketSpace::new(Instant::now());
        queue(&mut space, client_hello(FIREFOX_FULL, "www.google.com"));
        let (first, outcome) = packet(CryptoFraming::SniSlicing, &mut space, 23, 1252, &mut rng);
        assert_eq!(first, [(1143, 765), (0, 189)]);
        assert!(outcome.end_datagram);
        assert_eq!(pending(&space), [(189, 954)]);
        let (second, outcome) = packet(CryptoFraming::SniSlicing, &mut space, 23, 1252, &mut rng);
        assert_eq!(second, [(189, 954)]);
        assert!(!outcome.end_datagram);
        assert!(space.pending.crypto.is_empty());
    }

    /// Firefox 156 to dl.google.com, where the server name comes late: the first packet carries
    /// the start of the ClientHello
    #[test]
    fn sni_slicing_late_server_name() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut space = PacketSpace::new(Instant::now());
        let hello = client_hello(FIREFOX_LATE_SNI, "dl.google.com");
        assert_eq!(hello.len(), 1907);
        queue(&mut space, hello);
        let (first, _) = packet(CryptoFraming::SniSlicing, &mut space, 22, 1252, &mut rng);
        assert_eq!(first, [(1501, 406), (0, 547)]);
        assert_eq!(pending(&space), [(547, 954)]);
    }

    /// Resumed Firefox 156 connection: 70-byte token, three Initial packets
    #[test]
    fn sni_slicing_resumed() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut space = PacketSpace::new(Instant::now());
        let hello = client_hello(FIREFOX_RESUMED, "www.google.com");
        assert_eq!(hello.len(), 2513);
        queue(&mut space, hello);
        let (first, _) = packet(CryptoFraming::SniSlicing, &mut space, 93, 1252, &mut rng);
        assert_eq!(first, [(1858, 655), (0, 182)]);
        let (second, _) = packet(CryptoFraming::SniSlicing, &mut space, 93, 1252, &mut rng);
        assert_eq!(second, [(182, 1138)]);
        let (third, _) = packet(CryptoFraming::SniSlicing, &mut space, 93, 1252, &mut rng);
        assert_eq!(third, [(1320, 538)]);
        assert!(space.pending.crypto.is_empty());
    }

    #[test]
    fn sni_slicing_without_server_name_is_in_order() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut space = PacketSpace::new(Instant::now());
        queue(&mut space, vec![0x55; 1500]);
        let (first, outcome) = packet(CryptoFraming::SniSlicing, &mut space, 23, 1252, &mut rng);
        assert_eq!(first, [(0, 1209)]);
        assert!(!outcome.end_datagram);
    }

    /// The amount of ClientHello data quiche puts into the first packet, for four ClientHellos of
    /// Chrome 153
    #[test]
    fn multi_packet_split_matches_capture() {
        // (ClientHello length, room in the first packet, bytes in the first packet)
        for (len, bytes_free, first_packet) in [
            (1948, 1215, 972),
            (1984, 1215, 990),
            (2483, 1144, 825),
            (2425, 1144, 805),
        ] {
            for random in 0..32 {
                let (first, last) = multi_packet_split(len, bytes_free, random).unwrap();
                assert_eq!(first, 55 + random);
                assert_eq!(first + last, first_packet);
            }
        }
        // Fits into one packet
        assert_eq!(multi_packet_split(1000, 1215, 0), None);
    }

    fn crypto_coverage(frames: &[(u64, usize)]) -> Vec<(u64, u64)> {
        let mut ranges = frames
            .iter()
            .filter(|(o, _)| *o != u64::MAX)
            .map(|&(o, l)| (o, o + l as u64))
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

    fn pings(frames: &[(u64, usize)]) -> usize {
        frames.iter().filter(|f| **f == (u64::MAX, 0)).count()
    }

    /// Chrome 153's first connection: a 1948-byte ClientHello in two Initial packets of 1250
    /// bytes (DCID 8, empty SCID, no token)
    #[test]
    fn chaos_protection_two_packets() {
        for seed in 0..50 {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut space = PacketSpace::new(Instant::now());
            queue(&mut space, vec![0x55; 1948]);

            let (first, outcome) = packet(
                CryptoFraming::ChaosProtection,
                &mut space,
                19,
                1250,
                &mut rng,
            );
            assert!(outcome.widen_next_pn);
            assert!(!outcome.end_datagram);
            let coverage = crypto_coverage(&first);
            assert_eq!(coverage.len(), 2);
            let (head, tail) = (coverage[0], coverage[1]);
            assert_eq!(head.0, 0);
            assert!((55..87).contains(&head.1));
            assert_eq!(tail.1, 1948);
            assert_eq!(head.1 + (tail.1 - tail.0), 972);
            assert!((2..=10).contains(&pings(&first)));
            // At least the two chunks, split up to ten more times
            let cryptos = first.iter().filter(|f| f.0 != u64::MAX).count();
            assert!((2..=12).contains(&cryptos));
            assert_eq!(pending(&space), [(head.1, (tail.0 - head.1) as usize)]);

            // Second packet with a two-byte packet number
            let (second, outcome) = packet(
                CryptoFraming::ChaosProtection,
                &mut space,
                20,
                1250,
                &mut rng,
            );
            assert!(!outcome.widen_next_pn);
            assert_eq!(crypto_coverage(&second), [(head.1, tail.0)]);
            assert!((2..=10).contains(&pings(&second)));
            assert!(space.pending.crypto.is_empty());
        }
    }

    /// Chrome 153's resumed connection: 2483 bytes with a 70-byte token in three packets, the
    /// middle one full and therefore without chaos protection
    #[test]
    fn chaos_protection_three_packets() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut space = PacketSpace::new(Instant::now());
        queue(&mut space, vec![0x55; 2483]);
        let (first, _) = packet(
            CryptoFraming::ChaosProtection,
            &mut space,
            90,
            1250,
            &mut rng,
        );
        let coverage = crypto_coverage(&first);
        let first_len = coverage[0].1;
        assert_eq!(coverage, [(0, first_len), (2483 - (825 - first_len), 2483)]);
        // Full, so without chaos protection: 1139 bytes as Chrome sends it, one less when the
        // offset needs a two-byte varint
        let (second, _) = packet(
            CryptoFraming::ChaosProtection,
            &mut space,
            91,
            1250,
            &mut rng,
        );
        let second_len = 1143 - crypto_header_len(first_len, 2483 - 825) as u64;
        assert_eq!(second, [(first_len, second_len as usize)]);
        let (third, _) = packet(
            CryptoFraming::ChaosProtection,
            &mut space,
            90,
            1250,
            &mut rng,
        );
        assert_eq!(
            crypto_coverage(&third),
            [(first_len + second_len, 2483 - (825 - first_len))]
        );
        assert!(pings(&third) >= 2);
    }

    /// Frames that were written before the CRYPTO data, e.g. an ACK, stay in front
    #[test]
    fn chaos_layout_keeps_prefix() {
        for seed in 0..100 {
            let mut rng = StdRng::seed_from_u64(seed);
            let layout = chaos_layout(
                vec![
                    ChaosFrame::Prefix,
                    ChaosFrame::Crypto {
                        offset: 0,
                        len: 300,
                    },
                ],
                500,
                &mut rng,
            );
            assert_eq!(layout[0], ChaosFrame::Prefix);
            let size: usize = layout
                .iter()
                .map(|f| match *f {
                    ChaosFrame::Prefix => 0,
                    ChaosFrame::Crypto { offset, len } => {
                        crypto_header_len(offset, len) + len as usize
                    }
                    ChaosFrame::Ping => 1,
                    ChaosFrame::Padding(n) => n,
                })
                .sum();
            // The original frame took 1 + 1 + 2 + 300 bytes, and nothing gets lost
            assert_eq!(size, 304 + 500);
        }
    }
}
