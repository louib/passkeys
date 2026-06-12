use crate::ctap_hid::{CtapHidPacket, CtapHidReassembler};
use log::{info, warn};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem;

// --- Linux UHID API Constants (from uhid.h) ---
const UHID_CREATE2: u32 = 11;
const UHID_OUTPUT: u32 = 6;
const BUS_USB: u16 = 0x03;
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const UHID_DATA_MAX: usize = 4096;

/// FIDO Alliance Usage Page (0xF1D0).
const USAGE_PAGE_FIDO: u8 = 0xd0;
/// U2F HID Authenticator Usage (0x01).
const USAGE_U2F_AUTHENTICATOR: u8 = 0x01;

/// FIDO2 HID Report Descriptor.
///
/// This informs the kernel that this device is a FIDO2 security key.
const FIDO_REPORT_DESC: &[u8] = &[
    0x06,
    USAGE_PAGE_FIDO,
    0xf1, // Usage Page (FIDO Alliance)
    0x09,
    USAGE_U2F_AUTHENTICATOR, // Usage (U2FHID)
    0xa1,
    0x01, // Collection (Application)
    0x09,
    0x20, //   Usage (Input Report Data)
    0x15,
    0x00, //   Logical Minimum (0)
    0x26,
    0xff,
    0x00, //   Logical Maximum (255)
    0x75,
    0x08, //   Report Size (8)
    0x95,
    0x40, //   Report Count (64)
    0x81,
    0x02, //   Input (Data, Var, Abs)
    0x09,
    0x21, //   Usage (Output Report Data)
    0x15,
    0x00, //   Logical Minimum (0)
    0x26,
    0xff,
    0x00, //   Logical Maximum (255)
    0x75,
    0x08, //   Report Size (8 bits)
    0x95,
    0x40, //   Report Count (64 bytes)
    0x91,
    0x02, //   Output (Data, Var, Abs)
    0xc0, // End Collection
];

// --- C-Compatible Structs (Zero-Dependency) ---

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct UhidCreate2Req {
    name: [u8; 128],
    phys: [u8; 64],
    uniq: [u8; 64],
    rd_size: u16,
    bus: u16,
    vendor: u32,
    product: u32,
    version: u32,
    country: u32,
    rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct UhidOutputReq {
    data: [u8; UHID_DATA_MAX],
    size: u16,
    rtype: u8,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
#[allow(dead_code)]
union UhidEventUnion {
    create2: UhidCreate2Req,
    output: UhidOutputReq,
    // Padding to the maximum possible event size in the kernel
    _padding: [u8; 4352],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct UhidEvent {
    event_type: u32,
    u: UhidEventUnion,
}

/// A pure-Rust scaffolding for a virtual FIDO2 authenticator over UHID.
pub struct UhidAuthenticator {
    file: File,
    reassembler: CtapHidReassembler,
}

impl UhidAuthenticator {
    /// Creates a new virtual authenticator by opening /dev/uhid.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        info!("Opening /dev/uhid (Pure-Rust)...");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")?;

        // 1. Prepare the Create Request
        let mut event: UhidEvent = unsafe { mem::zeroed() };
        event.event_type = UHID_CREATE2;

        unsafe {
            let req = &mut event.u.create2;
            let name = b"MPC Passkey Pure-Rust Device";
            req.name[..name.len()].copy_from_slice(name);
            req.bus = BUS_USB;
            req.vendor = 0x1234;
            req.product = 0x5678;
            req.rd_size = FIDO_REPORT_DESC.len() as u16;
            req.rd_data[..FIDO_REPORT_DESC.len()].copy_from_slice(FIDO_REPORT_DESC);
        }

        // 2. Write the event to /dev/uhid to register the device
        let buf = unsafe {
            std::slice::from_raw_parts(&event as *const _ as *const u8, mem::size_of::<UhidEvent>())
        };
        file.write_all(buf)?;
        info!("Virtual device created successfully.");

        Ok(Self {
            file,
            reassembler: CtapHidReassembler::new(),
        })
    }

    /// Listens for HID events from the kernel and logs them.
    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Listening for HID events. Use https://webauthn.io to test.");

        let mut buf = vec![0u8; mem::size_of::<UhidEvent>()];

        loop {
            let n = self.file.read(&mut buf)?;
            if n < 4 {
                continue;
            }

            // Extract the 4-byte event type
            let event_type = u32::from_ne_bytes(buf[0..4].try_into().unwrap());

            if event_type == UHID_OUTPUT {
                info!("Packet Received! The browser is talking to our Rust binary.");

                // Safety: UhidEvent is repr(C, packed). We cast the buffer to access the output data.
                let event: &UhidEvent = unsafe { &*(buf.as_ptr() as *const UhidEvent) };
                let output = unsafe { &event.u.output };
                let report_data = &output.data[..output.size as usize];

                if let Some(packet) = CtapHidPacket::parse(report_data) {
                    if let Some(message) = self.reassembler.handle_packet(packet) {
                        info!("Full CTAP HID Message received: {:?}", message);
                        warn!("Next: Implement the CTAP2 CBOR command handler.");
                    }
                } else {
                    warn!("Failed to parse CTAP HID packet.");
                }
            }
        }
    }
}
