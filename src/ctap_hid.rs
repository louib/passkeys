//! CTAP HID (FIDO2) packet definitions and parsing.
//!
//! This module implements the packet format used for CTAP2 messages over HID,
//! as defined in the FIDO Alliance CTAP specification.

use std::collections::HashMap;

pub const CTAP_HID_REPORT_SIZE: usize = 64;

/// CTAP HID Command identifiers.
pub mod command {
    pub const MSG: u8 = 0x83;
    pub const CBOR: u8 = 0x90;
    pub const INIT: u8 = 0x86;
    pub const WINK: u8 = 0x81;
    pub const LOCK: u8 = 0x84;
    pub const CANCEL: u8 = 0x91;
    pub const KEEPALIVE: u8 = 0xbb;
    pub const ERROR: u8 = 0xbf;
}

/// A CTAP HID packet, which can be either an Initialization or a Continuation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtapHidPacket {
    Init(CtapHidInitPacket),
    Cont(CtapHidContPacket),
}

/// An Initialization packet (first packet of a message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidInitPacket {
    /// Channel Identifier.
    pub cid: u32,
    /// Command identifier (with bit 7 set).
    pub cmd: u8,
    /// Total payload length (big-endian).
    pub bcnt: u16,
    /// Payload data (up to 57 bytes).
    pub data: [u8; 57],
}

/// A Continuation packet (subsequent packets of a message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidContPacket {
    /// Channel Identifier.
    pub cid: u32,
    /// Sequence number (0x00 to 0x7f).
    pub seq: u8,
    /// Payload data (up to 59 bytes).
    pub data: [u8; 59],
}

/// A complete CTAP HID message, reassembled from one or more packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidMessage {
    /// Channel Identifier.
    pub cid: u32,
    /// Command identifier.
    pub cmd: u8,
    /// Full message payload.
    pub payload: Vec<u8>,
}

/// Helper to reassemble CTAP HID packets into complete messages.
#[derive(Default)]
pub struct CtapHidReassembler {
    channels: HashMap<u32, IncompleteMessage>,
}

struct IncompleteMessage {
    cmd: u8,
    bcnt: usize,
    payload: Vec<u8>,
    next_seq: u8,
}

impl CtapHidPacket {
    /// Parses a raw HID report (expected to be 64 bytes) into a `CtapHidPacket`.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 5 {
            return None;
        }

        let cid = u32::from_be_bytes(buf[0..4].try_into().ok()?);
        let first_byte = buf[4];

        if first_byte & 0x80 != 0 {
            // Initialization Packet
            if buf.len() < 7 {
                return None;
            }
            let cmd = first_byte;
            let bcnt = u16::from_be_bytes(buf[5..7].try_into().ok()?);
            let mut data = [0u8; 57];

            // The data starts at index 7. We copy up to 57 bytes.
            let available_data = &buf[7..];
            let copy_len = available_data.len().min(57);
            data[..copy_len].copy_from_slice(&available_data[..copy_len]);

            Some(CtapHidPacket::Init(CtapHidInitPacket {
                cid,
                cmd,
                bcnt,
                data,
            }))
        } else {
            // Continuation Packet
            let seq = first_byte;
            let mut data = [0u8; 59];

            // The data starts at index 5. We copy up to 59 bytes.
            let available_data = &buf[5..];
            let copy_len = available_data.len().min(59);
            data[..copy_len].copy_from_slice(&available_data[..copy_len]);

            Some(CtapHidPacket::Cont(CtapHidContPacket { cid, seq, data }))
        }
    }
}

impl CtapHidReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes a single packet and returns a complete message if it's finished.
    pub fn handle_packet(&mut self, packet: CtapHidPacket) -> Option<CtapHidMessage> {
        match packet {
            CtapHidPacket::Init(init) => {
                if init.bcnt as usize <= init.data.len() {
                    // Fits in one packet
                    Some(CtapHidMessage {
                        cid: init.cid,
                        cmd: init.cmd,
                        payload: init.data[..init.bcnt as usize].to_vec(),
                    })
                } else {
                    let mut payload = Vec::with_capacity(init.bcnt as usize);
                    payload.extend_from_slice(&init.data);
                    self.channels.insert(
                        init.cid,
                        IncompleteMessage {
                            cmd: init.cmd,
                            bcnt: init.bcnt as usize,
                            payload,
                            next_seq: 0,
                        },
                    );
                    None
                }
            }
            CtapHidPacket::Cont(cont) => {
                if let Some(msg) = self.channels.get_mut(&cont.cid) {
                    if cont.seq != msg.next_seq {
                        // Out of order packet, discard message
                        self.channels.remove(&cont.cid);
                        return None;
                    }

                    let remaining = msg.bcnt - msg.payload.len();
                    let copy_len = remaining.min(cont.data.len());
                    msg.payload.extend_from_slice(&cont.data[..copy_len]);
                    msg.next_seq += 1;

                    if msg.payload.len() >= msg.bcnt {
                        let msg = self.channels.remove(&cont.cid).unwrap();
                        Some(CtapHidMessage {
                            cid: cont.cid,
                            cmd: msg.cmd,
                            payload: msg.payload,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }
}
