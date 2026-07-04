use crate::ctap_hid::{CtapHidMessage, CtapHidPacket, CtapHidReassembler, command};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use log::{info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;

// --- Linux UHID API Constants (from uhid.h) ---
const UHID_CREATE2: u32 = 11;
const UHID_OUTPUT: u32 = 6;
const UHID_INPUT2: u32 = 12;
const BUS_USB: u16 = 0x03;
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const UHID_DATA_MAX: usize = 4096;

/// CTAP HID capability bit: authenticator supports CTAP2 CBOR commands.
const CTAP_HID_CAPABILITY_CBOR: u8 = 0x04;

/// CTAP2 authenticatorGetInfo response key: supported protocol versions.
const CTAP2_GET_INFO_VERSIONS: i64 = 1;
/// CTAP2 authenticatorGetInfo response key: authenticator AAGUID.
const CTAP2_GET_INFO_AAGUID: i64 = 3;
/// CTAP2 authenticatorGetInfo response key: supported authenticator options.
const CTAP2_GET_INFO_OPTIONS: i64 = 4;
/// CTAP2 authenticatorGetInfo response key: supported credential algorithms.
const CTAP2_GET_INFO_ALGORITHMS: i64 = 10;
/// CTAP2 authenticatorMakeCredential request key: relying party entity.
const CTAP2_MAKE_CREDENTIAL_RP: i64 = 2;
/// CTAP2 authenticatorMakeCredential response key: attestation statement format.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_FMT: i64 = 1;
/// CTAP2 authenticatorMakeCredential response key: authenticator data.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_AUTH_DATA: i64 = 2;
/// CTAP2 authenticatorMakeCredential response key: attestation statement.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_ATT_STMT: i64 = 3;
const CTAP2_VERSION_FIDO_2_0: &str = "FIDO_2_0";
const CTAP2_VERSION_FIDO_2_1_PRE: &str = "FIDO_2_1_PRE";
const CTAP2_STATUS_OK: u8 = 0x00;
const CTAP2_STATUS_OPERATION_DENIED: u8 = 0x27;

/// COSE key parameter: key type (`kty`).
const COSE_KEY_TYPE: i64 = 1;
/// COSE key parameter: signing algorithm (`alg`).
const COSE_KEY_ALGORITHM: i64 = 3;
/// COSE key parameter: elliptic curve (`crv`).
const COSE_KEY_CURVE: i64 = -1;
/// COSE key parameter: public key x-coordinate.
const COSE_KEY_X_COORDINATE: i64 = -2;
/// COSE key type value for octet key pairs (`OKP`).
const COSE_KEY_TYPE_OKP: i64 = 1;
/// COSE algorithm value for EdDSA.
const COSE_ALGORITHM_EDDSA: i64 = -8;
/// COSE curve value for Ed25519.
const COSE_CURVE_ED25519: i64 = 6;
/// U2F APDU instruction: register.
const U2F_APDU_REGISTER: u8 = 0x01;
/// U2F APDU instruction: version.
const U2F_APDU_VERSION: u8 = 0x03;
/// Chrome's synthetic U2F register probe uses P1=0x03.
const U2F_REGISTER_PROBE_P1: u8 = 0x03;
/// APDU status word: command completed successfully.
const APDU_SW_NO_ERROR: [u8; 2] = [0x90, 0x00];
/// APDU status word: user presence or similar condition is not currently satisfied.
const APDU_SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
/// APDU status word: instruction is not supported.
const APDU_SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6d, 0x00];
/// U2F register response reserved byte.
const U2F_REGISTER_RESPONSE_RESERVED: u8 = 0x05;
/// U2F public keys are uncompressed P-256 points.
const U2F_PUBLIC_KEY_LEN: usize = 65;
const U2F_DUMMY_KEY_HANDLE: &[u8] = b"chrome-presence-probe";
const U2F_DUMMY_ATTESTATION_CERT_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x00];
const U2F_DUMMY_SIGNATURE_DER: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// FIDO Alliance Usage Page (0xF1D0).
const USAGE_PAGE_FIDO: u8 = 0xd0;
/// U2F HID Authenticator Usage (0x01).
const USAGE_U2F_AUTHENTICATOR: u8 = 0x01;

mod ctap2_command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const SELECTION: u8 = 0x0b;
}

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
    size: u16,
    data: [u8; UHID_DATA_MAX],
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
                let report_len = available_data.min(65);
                let report_data = &buf[data_start..data_start + report_len];

                if let Some(packet) = CtapHidPacket::parse(report_data) {
                    info!("Successfully parsed packet: {:?}", packet);
                    if let Some(message) = self.reassembler.handle_packet(packet) {
                        info!(
                            "Full message received: cmd=0x{:02x}, payload_len={}",
                            message.cmd,
                            message.payload.len()
                        );
                        self.handle_message(message)?;
                    }
                } else {
                    warn!("Failed to parse packet from raw data: {:02x?}", report_data);
                }
            }
        }
    }

    fn handle_message(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        match message.cmd {
            command::PING => {
                info!("Handling CTAP_HID_PING");
                let response = CtapHidMessage {
                    cid: message.cid,
                    cmd: command::PING,
                    payload: message.payload,
                };
                self.send_message(response)?;
            }
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
                let capabilities = CTAP_HID_CAPABILITY_CBOR;
                response_payload.push(capabilities);
                info!("CTAP_HID_INIT capabilities=0x{:02x}", capabilities);

                let response = CtapHidMessage {
                    cid: message.cid,
                    cmd: command::INIT,
                    payload: response_payload,
                };
                self.send_message(response)?;
            }
            command::WINK => {
                info!("Handling CTAP_HID_WINK");
                let response = CtapHidMessage {
                    cid: message.cid,
                    cmd: command::WINK,
                    payload: Vec::new(),
                };
                self.send_message(response)?;
            }
            command::MSG => {
                self.handle_u2f_msg(message)?;
            }
            command::CBOR => {
                info!("Handling CTAP_HID_CBOR");
                if message.payload.is_empty() {
                    warn!("Empty CBOR payload");
                    return Ok(());
                }

                let ctap_cmd = message.payload[0];
                match ctap_cmd {
                    ctap2_command::GET_INFO => {
                        // authenticatorGetInfo
                        info!("CTAP2 Command: authenticatorGetInfo");

                        let mut map = Vec::new();
                        // 1: versions
                        map.push((
                            Value::Integer(CTAP2_GET_INFO_VERSIONS.into()),
                            Value::Array(vec![
                                Value::Text(CTAP2_VERSION_FIDO_2_0.into()),
                                Value::Text(CTAP2_VERSION_FIDO_2_1_PRE.into()),
                            ]),
                        ));
                        // 3: aaguid (16 bytes)
                        map.push((
                            Value::Integer(CTAP2_GET_INFO_AAGUID.into()),
                            Value::Bytes(vec![0u8; 16]),
                        ));
                        // 4: options
                        let mut options = Vec::new();
                        options.push((Value::Text("rk".into()), Value::Bool(false)));
                        options.push((Value::Text("up".into()), Value::Bool(true)));
                        options.push((Value::Text("uv".into()), Value::Bool(false)));
                        options.push((Value::Text("clientPin".into()), Value::Bool(false)));
                        map.push((
                            Value::Integer(CTAP2_GET_INFO_OPTIONS.into()),
                            Value::Map(options),
                        ));
                        // 10: algorithms
                        map.push((
                            Value::Integer(CTAP2_GET_INFO_ALGORITHMS.into()),
                            Value::Array(vec![Value::Map(vec![
                                (Value::Text("type".into()), Value::Text("public-key".into())),
                                (
                                    Value::Text("alg".into()),
                                    Value::Integer(COSE_ALGORITHM_EDDSA.into()),
                                ),
                            ])]),
                        ));

                        let mut payload = Vec::new();
                        payload.push(CTAP2_STATUS_OK);
                        ciborium::ser::into_writer(&Value::Map(map), &mut payload)?;

                        let response = CtapHidMessage {
                            cid: message.cid,
                            cmd: command::CBOR,
                            payload,
                        };
                        self.send_message(response)?;
                    }
                    ctap2_command::MAKE_CREDENTIAL => {
                        // authenticatorMakeCredential
                        info!("CTAP2 Command: authenticatorMakeCredential");
                        if !Self::confirm_user_presence("Register this passkey?")? {
                            warn!("User denied authenticatorMakeCredential");
                            self.send_cbor_status(message.cid, CTAP2_STATUS_OPERATION_DENIED)?;
                            return Ok(());
                        }

                        let mut rng = rand::thread_rng();
                        let signing_key = SigningKey::generate(&mut rng);
                        let public_key = signing_key.verifying_key();
                        let rp_id = Self::make_credential_rp_id(&message.payload)?
                            .unwrap_or_else(|| "unknown".into());
                        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
                        info!("MakeCredential rp.id={}", rp_id);

                        let mut auth_data = Vec::new();
                        auth_data.extend_from_slice(&rp_id_hash);
                        auth_data.push(0b01000001); // flags
                        auth_data.extend_from_slice(&[0u8; 4]); // signCount
                        auth_data.extend_from_slice(&[0u8; 16]); // aaguid

                        let cred_id = b"dummy-credential-id";
                        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
                        auth_data.extend_from_slice(cred_id);

                        let mut cose_key = Vec::new();
                        cose_key.push((
                            Value::Integer(COSE_KEY_TYPE.into()),
                            Value::Integer(COSE_KEY_TYPE_OKP.into()),
                        ));
                        cose_key.push((
                            Value::Integer(COSE_KEY_ALGORITHM.into()),
                            Value::Integer(COSE_ALGORITHM_EDDSA.into()),
                        ));
                        cose_key.push((
                            Value::Integer(COSE_KEY_CURVE.into()),
                            Value::Integer(COSE_CURVE_ED25519.into()),
                        ));
                        cose_key.push((
                            Value::Integer(COSE_KEY_X_COORDINATE.into()),
                            Value::Bytes(public_key.to_bytes().to_vec()),
                        )); // x

                        let mut cose_buf = Vec::new();
                        ciborium::ser::into_writer(&Value::Map(cose_key), &mut cose_buf)?;
                        auth_data.extend_from_slice(&cose_buf);

                        let mut attestation = Vec::new();
                        attestation.push((
                            Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_FMT.into()),
                            Value::Text("none".into()),
                        ));
                        attestation.push((
                            Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_AUTH_DATA.into()),
                            Value::Bytes(auth_data),
                        ));
                        attestation.push((
                            Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_ATT_STMT.into()),
                            Value::Map(vec![]),
                        ));

                        let mut payload = Vec::new();
                        payload.push(CTAP2_STATUS_OK);
                        ciborium::ser::into_writer(&Value::Map(attestation), &mut payload)?;

                        let response = CtapHidMessage {
                            cid: message.cid,
                            cmd: command::CBOR,
                            payload,
                        };
                        self.send_message(response)?;
                    }
                    ctap2_command::GET_ASSERTION => {
                        warn!("CTAP2 Command authenticatorGetAssertion is not implemented");
                    }
                    ctap2_command::CLIENT_PIN => {
                        warn!("CTAP2 Command authenticatorClientPIN is not implemented");
                    }
                    ctap2_command::SELECTION => {
                        info!("CTAP2 Command: authenticatorSelection");
                        let status = if Self::confirm_user_presence("Use this authenticator?")? {
                            CTAP2_STATUS_OK
                        } else {
                            CTAP2_STATUS_OPERATION_DENIED
                        };
                        self.send_cbor_status(message.cid, status)?;
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

    fn handle_u2f_msg(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        info!("Handling CTAP_HID_MSG");

        let instruction = message.payload.get(1).copied();
        let parameter_1 = message.payload.get(2).copied();
        let mut payload = Vec::new();

        match (instruction, parameter_1) {
            (Some(U2F_APDU_VERSION), _) => {
                info!("U2F APDU VERSION");
                payload.extend_from_slice(b"U2F_V2");
                payload.extend_from_slice(&APDU_SW_NO_ERROR);
            }
            (Some(U2F_APDU_REGISTER), Some(U2F_REGISTER_PROBE_P1)) => {
                info!("Chrome U2F register probe");
                if Self::confirm_user_presence("Allow Chrome's registration presence probe?")? {
                    payload.extend_from_slice(&Self::dummy_u2f_register_response());
                } else {
                    payload.extend_from_slice(&APDU_SW_CONDITIONS_NOT_SATISFIED);
                }
            }
            (Some(U2F_APDU_REGISTER), _) => {
                warn!("U2F APDU REGISTER is not implemented");
                payload.extend_from_slice(&APDU_SW_INS_NOT_SUPPORTED);
            }
            (Some(ins), _) => {
                warn!("Unhandled U2F APDU instruction: 0x{:02x}", ins);
                payload.extend_from_slice(&APDU_SW_INS_NOT_SUPPORTED);
            }
            (None, _) => {
                warn!("U2F APDU payload too short");
                payload.extend_from_slice(&APDU_SW_INS_NOT_SUPPORTED);
            }
        }

        let response = CtapHidMessage {
            cid: message.cid,
            cmd: command::MSG,
            payload,
        };
        self.send_message(response)
    }

    fn dummy_u2f_register_response() -> Vec<u8> {
        let mut response = Vec::new();
        response.push(U2F_REGISTER_RESPONSE_RESERVED);

        let mut public_key = [0u8; U2F_PUBLIC_KEY_LEN];
        public_key[0] = 0x04;
        public_key[1..].fill(0x42);
        response.extend_from_slice(&public_key);

        response.push(U2F_DUMMY_KEY_HANDLE.len() as u8);
        response.extend_from_slice(U2F_DUMMY_KEY_HANDLE);
        response.extend_from_slice(U2F_DUMMY_ATTESTATION_CERT_DER);
        response.extend_from_slice(U2F_DUMMY_SIGNATURE_DER);
        response.extend_from_slice(&APDU_SW_NO_ERROR);
        response
    }

    fn make_credential_rp_id(payload: &[u8]) -> Result<Option<String>, Box<dyn Error>> {
        if payload.len() < 2 {
            return Ok(None);
        }

        let request: Value = ciborium::de::from_reader(&payload[1..])?;
        let Value::Map(entries) = request else {
            return Ok(None);
        };

        for (key, value) in entries {
            if key != Value::Integer(CTAP2_MAKE_CREDENTIAL_RP.into()) {
                continue;
            }

            let Value::Map(rp_entries) = value else {
                return Ok(None);
            };

            for (rp_key, rp_value) in rp_entries {
                if rp_key == Value::Text("id".into()) {
                    if let Value::Text(rp_id) = rp_value {
                        return Ok(Some(rp_id));
                    }
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    fn send_cbor_status(&mut self, cid: u32, status: u8) -> Result<(), Box<dyn Error>> {
        let response = CtapHidMessage {
            cid,
            cmd: command::CBOR,
            payload: vec![status],
        };
        self.send_message(response)
    }

    fn confirm_user_presence(prompt: &str) -> Result<bool, Box<dyn Error>> {
        loop {
            print!("{prompt} [y/n]: ");
            io::stdout().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;

            match answer.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => {
                    println!("Please answer y or n.");
                }
            }
        }
    }

    fn send_message(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        info!(
            "Sending message: cmd=0x{:02x}, payload_len={}",
            message.cmd,
            message.payload.len()
        );
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

            // Log fields by copying them first to avoid unaligned reference errors in packed structs
            let ev_type = event.event_type;
            let req_size = unsafe { event.u.input2.size };
            info!(
                "Writing to /dev/uhid ({} bytes): event_type={}, size={}",
                buf.len(),
                ev_type,
                req_size
            );
            self.file.write_all(buf)?;
        }
        info!("Message sent successfully.");
        Ok(())
    }
}
