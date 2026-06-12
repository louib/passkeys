use crate::ctap_hid::{CtapHidMessage, CtapHidPacket, CtapHidReassembler, command};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use log::{info, warn};
use rand::RngCore;
use sha2::Sha256;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem;

// --- Linux UHID API Constants (from uhid.h) ---
const UHID_CREATE2: u32 = 11;
const UHID_OUTPUT: u32 = 6;
const UHID_INPUT2: u32 = 12;
const BUS_USB: u16 = 0x03;
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const UHID_DATA_MAX: usize = 4096;

/// FIDO Alliance Usage Page (0xF1D0).
const USAGE_PAGE_FIDO: u8 = 0xd0;
/// U2F HID Authenticator Usage (0x01).
const USAGE_U2F_AUTHENTICATOR: u8 = 0x01;

/// FIDO2 HID Report Descriptor.
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
struct UhidInput2Req {
    data: [u8; UHID_DATA_MAX],
    size: u16,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
#[allow(dead_code)]
union UhidEventUnion {
    create2: UhidCreate2Req,
    output: UhidOutputReq,
    input2: UhidInput2Req,
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
                info!("UHID_OUTPUT event received ({} bytes read)", n);

                let data_start = 4;
                let available_data = n.saturating_sub(data_start);
                let report_len = available_data.min(64);
                let report_data = &buf[data_start..data_start + report_len];

                if let Some(packet) = CtapHidPacket::parse(report_data) {
                    if let Some(message) = self.reassembler.handle_packet(packet) {
                        info!(
                            "Full message received: cmd=0x{:02x}, payload_len={}",
                            message.cmd,
                            message.payload.len()
                        );
                        self.handle_message(message)?;
                    }
                }
            }
        }
    }

    fn handle_message(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        match message.cmd {
            command::INIT => {
                info!("Handling CTAP_HID_INIT");
                if message.payload.len() < 8 {
                    warn!("INIT payload too short");
                    return Ok(());
                }
                let nonce = &message.payload[..8];
                let mut new_cid = [0u8; 4];
                rand::thread_rng().fill_bytes(&mut new_cid);

                let mut response_payload = Vec::new();
                response_payload.extend_from_slice(nonce);
                response_payload.extend_from_slice(&new_cid);
                response_payload.push(0x02); // Protocol version
                response_payload.push(0x01); // Version major
                response_payload.push(0x00); // Version minor
                response_payload.push(0x00); // Version build
                response_payload.push(0x01); // Capabilities (WINK)

                let response = CtapHidMessage {
                    cid: message.cid,
                    cmd: command::INIT,
                    payload: response_payload,
                };
                self.send_message(response)?;
            }
            command::CBOR => {
                info!("Handling CTAP_HID_CBOR");
                if message.payload.is_empty() {
                    warn!("Empty CBOR payload");
                    return Ok(());
                }

                let ctap_cmd = message.payload[0];
                match ctap_cmd {
                    0x06 => {
                        // authenticatorGetInfo
                        info!("CTAP2 Command: authenticatorGetInfo");

                        let mut map = Vec::new();
                        // 1: versions
                        map.push((
                            Value::Integer(1.into()),
                            Value::Array(vec![
                                Value::Text("FIDO_2_0".into()),
                                Value::Text("FIDO_2_1".into()),
                            ]),
                        ));
                        // 2: extensions
                        map.push((
                            Value::Integer(2.into()),
                            Value::Array(vec![Value::Text("credProtect".into())]),
                        ));
                        // 3: aaguid (16 bytes)
                        map.push((Value::Integer(3.into()), Value::Bytes(vec![0u8; 16])));
                        // 4: options
                        let mut options = Vec::new();
                        options.push((Value::Text("rk".into()), Value::Bool(true)));
                        options.push((Value::Text("up".into()), Value::Bool(true)));
                        options.push((Value::Text("uv".into()), Value::Bool(true)));
                        map.push((Value::Integer(4.into()), Value::Map(options)));

                        // 6: algorithms
                        let mut alg = Vec::new();
                        alg.push((Value::Text("type".into()), Value::Text("public-key".into())));
                        alg.push((Value::Text("alg".into()), Value::Integer((-8).into()))); // EdDSA
                        map.push((
                            Value::Integer(6.into()),
                            Value::Array(vec![Value::Map(alg)]),
                        ));

                        let mut payload = Vec::new();
                        payload.push(0x00); // Status: CTAP2_OK
                        ciborium::ser::into_writer(&Value::Map(map), &mut payload)?;

                        let response = CtapHidMessage {
                            cid: message.cid,
                            cmd: command::CBOR,
                            payload,
                        };
                        self.send_message(response)?;
                    }
                    0x01 => {
                        // authenticatorMakeCredential
                        info!("CTAP2 Command: authenticatorMakeCredential");

                        // 1. Generate Ed25519 Key Pair
                        let mut rng = rand::thread_rng();
                        let signing_key = SigningKey::generate(&mut rng);
                        let public_key = signing_key.verifying_key();

                        // 2. Construct authData
                        let mut auth_data = Vec::new();

                        // rpIdHash (32 bytes) - Placeholder for SHA256(rpId)
                        auth_data.extend_from_slice(&[0u8; 32]);

                        // flags (1 byte): UP (bit 0), AT (bit 6)
                        auth_data.push(0b01000001);

                        // signCount (4 bytes)
                        auth_data.extend_from_slice(&[0u8; 4]);

                        // aaguid (16 bytes)
                        auth_data.extend_from_slice(&[0u8; 16]);

                        // L (2 bytes): Credential ID length
                        let cred_id = b"dummy-credential-id";
                        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());

                        // credentialId
                        auth_data.extend_from_slice(cred_id);

                        // credentialPublicKey (COSE)
                        let mut cose_key = Vec::new();
                        cose_key.push((Value::Integer(1.into()), Value::Integer(1.into()))); // kty: OKP
                        cose_key.push((Value::Integer(3.into()), Value::Integer((-8).into()))); // alg: EdDSA
                        cose_key.push((Value::Integer((-1).into()), Value::Integer(6.into()))); // crv: Ed25519
                        cose_key.push((
                            Value::Integer((-2).into()),
                            Value::Bytes(public_key.to_bytes().to_vec()),
                        )); // x

                        let mut cose_buf = Vec::new();
                        ciborium::ser::into_writer(&Value::Map(cose_key), &mut cose_buf)?;
                        auth_data.extend_from_slice(&cose_buf);

                        // 3. Construct Attestation Object
                        let mut attestation = Vec::new();
                        attestation.push((Value::Text("fmt".into()), Value::Text("none".into())));
                        attestation.push((Value::Text("attStmt".into()), Value::Map(vec![])));
                        attestation.push((Value::Text("authData".into()), Value::Bytes(auth_data)));

                        let mut payload = Vec::new();
                        payload.push(0x00); // Status: CTAP2_OK
                        ciborium::ser::into_writer(&Value::Map(attestation), &mut payload)?;

                        let response = CtapHidMessage {
                            cid: message.cid,
                            cmd: command::CBOR,
                            payload,
                        };
                        self.send_message(response)?;
                    }
                    _ => {
                        warn!("Unhandled CTAP2 command: 0x{:02x}", ctap_cmd);
                    }
                }
            }
            _ => {
                warn!("Unhandled CTAP HID command: 0x{:02x}", message.cmd);
            }
        }
        Ok(())
    }

    fn send_message(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        let packets = message.to_packets();
        for packet in packets {
            let report = packet.serialize();

            let mut event: UhidEvent = unsafe { mem::zeroed() };
            event.event_type = UHID_INPUT2;
            unsafe {
                let req = &mut event.u.input2;
                req.size = 64;
                req.data[..64].copy_from_slice(&report);
            }

            let buf = unsafe {
                std::slice::from_raw_parts(
                    &event as *const _ as *const u8,
                    mem::size_of::<UhidEvent>(),
                )
            };
            self.file.write_all(buf)?;
        }
        Ok(())
    }
}
