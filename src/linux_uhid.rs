use crate::authenticator::{AssertionRequest, AuthenticatorService, RegistrationRequest};
use crate::backend::{CredentialBackend, LocalEd25519Backend};
use crate::ctap_hid::{CtapHidMessage, CtapHidPacket, CtapHidReassembler, command};
use ciborium::value::Value;
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
/// CTAP HID capability bit: authenticator does not support legacy CTAP1/U2F
/// messages over CTAPHID_MSG.
const CTAP_HID_CAPABILITY_NMSG: u8 = 0x08;

/// CTAP2 authenticatorGetInfo response key: supported protocol versions.
const CTAP2_GET_INFO_VERSIONS: i64 = 1;
/// CTAP2 authenticatorGetInfo response key: authenticator AAGUID.
const CTAP2_GET_INFO_AAGUID: i64 = 3;
/// CTAP2 authenticatorGetInfo response key: supported authenticator options.
const CTAP2_GET_INFO_OPTIONS: i64 = 4;
/// CTAP2 authenticatorMakeCredential request key: relying party entity.
const CTAP2_MAKE_CREDENTIAL_RP: i64 = 2;
/// CTAP2 authenticatorMakeCredential request key: user entity.
const CTAP2_MAKE_CREDENTIAL_USER: i64 = 3;
/// CTAP2 authenticatorMakeCredential request key: accepted credential parameters.
const CTAP2_MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS: i64 = 4;
/// CTAP2 authenticatorMakeCredential response key: attestation statement format.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_FMT: i64 = 1;
/// CTAP2 authenticatorMakeCredential response key: authenticator data.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_AUTH_DATA: i64 = 2;
/// CTAP2 authenticatorMakeCredential response key: attestation statement.
const CTAP2_MAKE_CREDENTIAL_RESPONSE_ATT_STMT: i64 = 3;
const CTAP2_VERSION_FIDO_2_0: &str = "FIDO_2_0";
const CTAP2_STATUS_OK: u8 = 0x00;
const CTAP2_STATUS_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_STATUS_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_STATUS_OPERATION_DENIED: u8 = 0x27;
const CTAP2_STATUS_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_STATUS_PIN_NOT_SET: u8 = 0x35;

/// Firefox/authenticator-rs uses this synthetic RP for CTAP 2.0 device
/// selection because CTAP 2.0 has no authenticatorSelection command.
const FIREFOX_SELECTION_RP_ID: &str = "make.me.blink";

const CTAP2_GET_ASSERTION_RP_ID: i64 = 1;
const CTAP2_GET_ASSERTION_CLIENT_DATA_HASH: i64 = 2;
const CTAP2_GET_ASSERTION_ALLOW_LIST: i64 = 3;
const CTAP2_GET_ASSERTION_OPTIONS: i64 = 5;
const CTAP2_GET_ASSERTION_RESPONSE_CREDENTIAL: i64 = 1;
const CTAP2_GET_ASSERTION_RESPONSE_AUTH_DATA: i64 = 2;
const CTAP2_GET_ASSERTION_RESPONSE_SIGNATURE: i64 = 3;

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
const U2F_APDU_REGISTER: u8 = 0x01;
const U2F_APDU_AUTHENTICATE: u8 = 0x02;
const U2F_APDU_VERSION: u8 = 0x03;
const U2F_REGISTER_P1_USER_PRESENCE: u8 = 0x03;
const APDU_SW_NO_ERROR: [u8; 2] = [0x90, 0x00];
const APDU_SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
const APDU_SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6d, 0x00];
const APDU_SW_WRONG_DATA: [u8; 2] = [0x6a, 0x80];
const U2F_REGISTER_RESPONSE_RESERVED: u8 = 0x05;
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
    authenticator: AuthenticatorService,
}

struct GetAssertionRequest {
    rp_id: String,
    client_data_hash: [u8; 32],
    allow_list: Vec<Vec<u8>>,
    user_presence: bool,
}

impl UhidAuthenticator {
    /// Creates a new virtual authenticator by opening /dev/uhid.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Self::with_backend(Box::new(LocalEd25519Backend::default()))
    }

    /// Creates a virtual authenticator backed by an injected credential
    /// implementation. The UHID and CTAP layers never access private keys.
    pub fn with_backend(backend: Box<dyn CredentialBackend>) -> Result<Self, Box<dyn Error>> {
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
            authenticator: AuthenticatorService::new(backend),
        })
    }

    /// Listens for HID events from the kernel and logs them.
    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Listening for HID events.");

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
                // This POC only implements CTAP2. Without NMSG, clients assume
                // CTAP1/U2F is also available and send legacy APDU probes that
                // this authenticator cannot answer correctly.
                let capabilities = CTAP_HID_CAPABILITY_CBOR | CTAP_HID_CAPABILITY_NMSG;
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
                // Chromium may still issue U2F compatibility probes after
                // observing NMSG. Handle them so one probe does not abort
                // discovery of the CTAP2 authenticator.
                self.handle_u2f_compatibility_message(message)?;
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
                        let payload = Self::get_info_payload()?;
                        info!(
                            "GetInfo response: versions=[{}], algorithms=<omitted>, options={{rk:false, up:true}}",
                            CTAP2_VERSION_FIDO_2_0
                        );

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
                        let Some(rp_id) = Self::make_credential_rp_id(&message.payload)? else {
                            warn!("MakeCredential request is missing rp.id");
                            self.send_cbor_status(message.cid, CTAP2_STATUS_MISSING_PARAMETER)?;
                            return Ok(());
                        };
                        let Some(user_id) = Self::make_credential_user_id(&message.payload)? else {
                            warn!("MakeCredential request is missing user.id");
                            self.send_cbor_status(message.cid, CTAP2_STATUS_MISSING_PARAMETER)?;
                            return Ok(());
                        };
                        let algorithms = Self::make_credential_algorithms(&message.payload)?;
                        info!("MakeCredential requested algorithms={algorithms:?}");

                        // Firefox's authenticator-rs sends a dummy ES256
                        // MakeCredential request to every connected CTAP 2.0
                        // authenticator when the user must choose a device. It
                        // considers PIN_NOT_SET after presence a successful
                        // selection and then sends the real RP request. Do not
                        // create or retain a credential for this probe.
                        if rp_id == FIREFOX_SELECTION_RP_ID {
                            info!("Firefox CTAP2 device-selection probe");
                            let status = if Self::confirm_user_presence(
                                "Use this authenticator for Firefox?",
                            )? {
                                CTAP2_STATUS_PIN_NOT_SET
                            } else {
                                CTAP2_STATUS_OPERATION_DENIED
                            };
                            self.send_cbor_status(message.cid, status)?;
                            return Ok(());
                        }

                        if !algorithms.contains(&COSE_ALGORITHM_EDDSA) {
                            warn!(
                                "MakeCredential does not offer supported algorithm {}",
                                COSE_ALGORITHM_EDDSA
                            );
                            self.send_cbor_status(message.cid, CTAP2_STATUS_UNSUPPORTED_ALGORITHM)?;
                            return Ok(());
                        }
                        if !Self::confirm_user_presence("Register this passkey?")? {
                            warn!("User denied authenticatorMakeCredential");
                            self.send_cbor_status(message.cid, CTAP2_STATUS_OPERATION_DENIED)?;
                            return Ok(());
                        }

                        info!("MakeCredential rp.id={}", rp_id);
                        let registration = self.authenticator.register(RegistrationRequest {
                            rp_id: &rp_id,
                            user_id: &user_id,
                        })?;
                        let payload = Self::make_credential_response(
                            &rp_id,
                            &registration.credential_id,
                            registration.public_key,
                        )?;
                        info!("Stored credential id={:02x?}", registration.credential_id);

                        let response = CtapHidMessage {
                            cid: message.cid,
                            cmd: command::CBOR,
                            payload,
                        };
                        self.send_message(response)?;
                    }
                    ctap2_command::GET_ASSERTION => {
                        info!("CTAP2 Command: authenticatorGetAssertion");
                        self.handle_get_assertion(message)?;
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

    fn get_info_payload() -> Result<Vec<u8>, Box<dyn Error>> {
        let map = vec![
            (
                Value::Integer(CTAP2_GET_INFO_VERSIONS.into()),
                Value::Array(vec![Value::Text(CTAP2_VERSION_FIDO_2_0.into())]),
            ),
            (
                Value::Integer(CTAP2_GET_INFO_AAGUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (
                Value::Integer(CTAP2_GET_INFO_OPTIONS.into()),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(false)),
                    (Value::Text("up".into()), Value::Bool(true)),
                ]),
            ),
        ];

        let mut payload = vec![CTAP2_STATUS_OK];
        ciborium::ser::into_writer(&Value::Map(map), &mut payload)?;
        Ok(payload)
    }

    fn handle_u2f_compatibility_message(
        &mut self,
        message: CtapHidMessage,
    ) -> Result<(), Box<dyn Error>> {
        info!("Handling CTAP_HID_MSG compatibility request");
        let instruction = message.payload.get(1).copied();
        let parameter_1 = message.payload.get(2).copied();
        let mut payload = Vec::new();

        match (instruction, parameter_1) {
            (Some(U2F_APDU_VERSION), _) => {
                payload.extend_from_slice(b"U2F_V2");
                payload.extend_from_slice(&APDU_SW_NO_ERROR);
            }
            (Some(U2F_APDU_AUTHENTICATE), _) => {
                info!("U2F compatibility credential probe: unknown key handle");
                payload.extend_from_slice(&APDU_SW_WRONG_DATA);
            }
            (Some(U2F_APDU_REGISTER), Some(U2F_REGISTER_P1_USER_PRESENCE)) => {
                info!("Chromium U2F compatibility registration request");
                if Self::confirm_user_presence("Allow Chromium's compatibility request?")? {
                    payload.extend_from_slice(&Self::dummy_u2f_register_response());
                } else {
                    payload.extend_from_slice(&APDU_SW_CONDITIONS_NOT_SATISFIED);
                }
            }
            (Some(U2F_APDU_REGISTER), _) => {
                payload.extend_from_slice(&APDU_SW_INS_NOT_SUPPORTED);
            }
            _ => payload.extend_from_slice(&APDU_SW_INS_NOT_SUPPORTED),
        }

        self.send_message(CtapHidMessage {
            cid: message.cid,
            cmd: command::MSG,
            payload,
        })
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

    fn make_credential_response(
        rp_id: &str,
        credential_id: &[u8],
        public_key: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut cose_buf = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (
                    Value::Integer(COSE_KEY_TYPE.into()),
                    Value::Integer(COSE_KEY_TYPE_OKP.into()),
                ),
                (
                    Value::Integer(COSE_KEY_ALGORITHM.into()),
                    Value::Integer(COSE_ALGORITHM_EDDSA.into()),
                ),
                (
                    Value::Integer(COSE_KEY_CURVE.into()),
                    Value::Integer(COSE_CURVE_ED25519.into()),
                ),
                (
                    Value::Integer(COSE_KEY_X_COORDINATE.into()),
                    Value::Bytes(public_key.to_vec()),
                ),
            ]),
            &mut cose_buf,
        )?;

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(0x41); // UP | AT
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        let credential_id_len = u16::try_from(credential_id.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "credential ID is too long")
        })?;
        auth_data.extend_from_slice(&credential_id_len.to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&cose_buf);

        let attestation = Value::Map(vec![
            (
                Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_FMT.into()),
                Value::Text("none".into()),
            ),
            (
                Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_AUTH_DATA.into()),
                Value::Bytes(auth_data),
            ),
            (
                Value::Integer(CTAP2_MAKE_CREDENTIAL_RESPONSE_ATT_STMT.into()),
                Value::Map(vec![]),
            ),
        ]);

        let mut payload = vec![CTAP2_STATUS_OK];
        ciborium::ser::into_writer(&attestation, &mut payload)?;
        Ok(payload)
    }

    fn handle_get_assertion(&mut self, message: CtapHidMessage) -> Result<(), Box<dyn Error>> {
        let Some(request) = Self::parse_get_assertion_request(&message.payload)? else {
            warn!("GetAssertion request is missing a required parameter");
            self.send_cbor_status(message.cid, CTAP2_STATUS_MISSING_PARAMETER)?;
            return Ok(());
        };

        info!(
            "GetAssertion rp.id={}, allow_list_entries={}, up={}",
            request.rp_id,
            request.allow_list.len(),
            request.user_presence
        );

        if !self
            .authenticator
            .has_matching_credential(&request.rp_id, &request.allow_list)
        {
            warn!("GetAssertion found no matching credential");
            self.send_cbor_status(message.cid, CTAP2_STATUS_NO_CREDENTIALS)?;
            return Ok(());
        }

        if request.user_presence && !Self::confirm_user_presence("Authenticate this passkey?")? {
            warn!("User denied authenticatorGetAssertion");
            self.send_cbor_status(message.cid, CTAP2_STATUS_OPERATION_DENIED)?;
            return Ok(());
        }

        let assertion = self.authenticator.assert(AssertionRequest {
            rp_id: &request.rp_id,
            client_data_hash: &request.client_data_hash,
            allow_list: &request.allow_list,
            user_present: request.user_presence,
        })?;

        let response = Value::Map(vec![
            (
                Value::Integer(CTAP2_GET_ASSERTION_RESPONSE_CREDENTIAL.into()),
                Value::Map(vec![
                    (
                        Value::Text("id".into()),
                        Value::Bytes(assertion.credential_id),
                    ),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ]),
            ),
            (
                Value::Integer(CTAP2_GET_ASSERTION_RESPONSE_AUTH_DATA.into()),
                Value::Bytes(assertion.authenticator_data),
            ),
            (
                Value::Integer(CTAP2_GET_ASSERTION_RESPONSE_SIGNATURE.into()),
                Value::Bytes(assertion.signature.to_vec()),
            ),
        ]);
        let mut payload = vec![CTAP2_STATUS_OK];
        ciborium::ser::into_writer(&response, &mut payload)?;
        info!(
            "GetAssertion signed credential, up={}, sign_count={}",
            request.user_presence, assertion.sign_count
        );
        self.send_message(CtapHidMessage {
            cid: message.cid,
            cmd: command::CBOR,
            payload,
        })
    }

    fn parse_get_assertion_request(
        payload: &[u8],
    ) -> Result<Option<GetAssertionRequest>, Box<dyn Error>> {
        if payload.len() < 2 {
            return Ok(None);
        }
        let Value::Map(entries) = ciborium::de::from_reader(&payload[1..])? else {
            return Ok(None);
        };

        let mut rp_id = None;
        let mut client_data_hash = None;
        let mut allow_list = Vec::new();
        let mut user_presence = true;

        for (key, value) in entries {
            if key == Value::Integer(CTAP2_GET_ASSERTION_RP_ID.into()) {
                if let Value::Text(value) = value {
                    rp_id = Some(value);
                }
            } else if key == Value::Integer(CTAP2_GET_ASSERTION_CLIENT_DATA_HASH.into()) {
                if let Value::Bytes(value) = value {
                    client_data_hash = value.try_into().ok();
                }
            } else if key == Value::Integer(CTAP2_GET_ASSERTION_ALLOW_LIST.into()) {
                if let Value::Array(descriptors) = value {
                    allow_list = descriptors
                        .into_iter()
                        .filter_map(Self::credential_descriptor_id)
                        .collect();
                }
            } else if key == Value::Integer(CTAP2_GET_ASSERTION_OPTIONS.into()) {
                if let Value::Map(options) = value {
                    for (option, value) in options {
                        if option == Value::Text("up".into()) {
                            if let Value::Bool(value) = value {
                                user_presence = value;
                            }
                        }
                    }
                }
            }
        }

        Ok(rp_id
            .zip(client_data_hash)
            .map(|(rp_id, client_data_hash)| GetAssertionRequest {
                rp_id,
                client_data_hash,
                allow_list,
                user_presence,
            }))
    }

    fn credential_descriptor_id(value: Value) -> Option<Vec<u8>> {
        let Value::Map(fields) = value else {
            return None;
        };
        fields.into_iter().find_map(|(key, value)| {
            if key == Value::Text("id".into()) {
                if let Value::Bytes(id) = value {
                    return Some(id);
                }
            }
            None
        })
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

    fn make_credential_user_id(payload: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        if payload.len() < 2 {
            return Ok(None);
        }

        let request: Value = ciborium::de::from_reader(&payload[1..])?;
        let Value::Map(entries) = request else {
            return Ok(None);
        };
        let Some(Value::Map(user_entries)) = entries.into_iter().find_map(|(key, value)| {
            (key == Value::Integer(CTAP2_MAKE_CREDENTIAL_USER.into())).then_some(value)
        }) else {
            return Ok(None);
        };

        Ok(user_entries.into_iter().find_map(|(key, value)| {
            (key == Value::Text("id".into()))
                .then_some(value)
                .and_then(|value| match value {
                    Value::Bytes(id) => Some(id),
                    _ => None,
                })
        }))
    }

    fn make_credential_algorithms(payload: &[u8]) -> Result<Vec<i64>, Box<dyn Error>> {
        if payload.len() < 2 {
            return Ok(Vec::new());
        }

        let request: Value = ciborium::de::from_reader(&payload[1..])?;
        let Value::Map(entries) = request else {
            return Ok(Vec::new());
        };

        let Some(Value::Array(parameters)) = entries.into_iter().find_map(|(key, value)| {
            (key == Value::Integer(CTAP2_MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS.into()))
                .then_some(value)
        }) else {
            return Ok(Vec::new());
        };

        let algorithms = parameters
            .into_iter()
            .filter_map(|parameter| {
                let Value::Map(fields) = parameter else {
                    return None;
                };
                fields.into_iter().find_map(|(key, value)| {
                    if key != Value::Text("alg".into()) {
                        return None;
                    }
                    let Value::Integer(algorithm) = value else {
                        return None;
                    };
                    i64::try_from(algorithm).ok()
                })
            })
            .collect();

        Ok(algorithms)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn map_value<'a>(map: &'a [(Value, Value)], key: i64) -> &'a Value {
        map.iter()
            .find_map(|(candidate, value)| {
                (candidate == &Value::Integer(key.into())).then_some(value)
            })
            .expect("GetInfo key should be present")
    }

    #[test]
    fn get_info_omits_optional_algorithm_prefilter() {
        let payload = UhidAuthenticator::get_info_payload().expect("GetInfo should encode");
        assert_eq!(payload[0], CTAP2_STATUS_OK);

        let value: Value =
            ciborium::de::from_reader(&payload[1..]).expect("GetInfo CBOR should decode");
        let Value::Map(map) = value else {
            panic!("GetInfo response should be a map");
        };
        assert_eq!(map.len(), 3);
        assert!(map.iter().all(|(key, _)| key != &Value::Integer(10.into())));
    }

    #[test]
    fn parses_make_credential_algorithm_list() {
        let request = Value::Map(vec![(
            Value::Integer(CTAP2_MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS.into()),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                ]),
                Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (
                        Value::Text("alg".into()),
                        Value::Integer(COSE_ALGORITHM_EDDSA.into()),
                    ),
                ]),
            ]),
        )]);
        let mut payload = vec![ctap2_command::MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&request, &mut payload).expect("request should encode");

        let algorithms = UhidAuthenticator::make_credential_algorithms(&payload)
            .expect("algorithm list should parse");
        assert_eq!(algorithms, vec![-7, COSE_ALGORITHM_EDDSA]);
    }

    #[test]
    fn parses_make_credential_user_id() {
        let request = Value::Map(vec![(
            Value::Integer(CTAP2_MAKE_CREDENTIAL_USER.into()),
            Value::Map(vec![(
                Value::Text("id".into()),
                Value::Bytes(b"user-id".to_vec()),
            )]),
        )]);
        let mut payload = vec![ctap2_command::MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&request, &mut payload).expect("request should encode");

        assert_eq!(
            UhidAuthenticator::make_credential_user_id(&payload)
                .expect("user should parse")
                .as_deref(),
            Some(b"user-id".as_slice())
        );
    }

    #[test]
    fn recognizes_firefox_device_selection_request_before_algorithm_filtering() {
        let request = Value::Map(vec![
            (
                Value::Integer(CTAP2_MAKE_CREDENTIAL_RP.into()),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text(FIREFOX_SELECTION_RP_ID.into()),
                )]),
            ),
            (
                Value::Integer(CTAP2_MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS.into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("alg".into()),
                    Value::Integer((-7).into()),
                )])]),
            ),
        ]);
        let mut payload = vec![ctap2_command::MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&request, &mut payload).expect("request should encode");

        assert_eq!(
            UhidAuthenticator::make_credential_rp_id(&payload)
                .expect("RP should parse")
                .as_deref(),
            Some(FIREFOX_SELECTION_RP_ID)
        );
        assert_eq!(
            UhidAuthenticator::make_credential_algorithms(&payload)
                .expect("algorithms should parse"),
            vec![-7]
        );
        assert_eq!(CTAP2_STATUS_PIN_NOT_SET, 0x35);
    }

    #[test]
    fn make_credential_response_contains_valid_ed25519_attested_data() {
        let credential_id = [0x5a; 32];
        let public_key = [0xa5; 32];
        let payload =
            UhidAuthenticator::make_credential_response("example.com", &credential_id, public_key)
                .expect("response should encode");
        assert_eq!(payload[0], CTAP2_STATUS_OK);

        let response: Value =
            ciborium::de::from_reader(&payload[1..]).expect("response CBOR should decode");
        let Value::Map(response) = response else {
            panic!("response should be a map");
        };
        assert_eq!(
            map_value(&response, CTAP2_MAKE_CREDENTIAL_RESPONSE_FMT),
            &Value::Text("none".into())
        );
        assert_eq!(
            map_value(&response, CTAP2_MAKE_CREDENTIAL_RESPONSE_ATT_STMT),
            &Value::Map(vec![])
        );

        let Value::Bytes(auth_data) =
            map_value(&response, CTAP2_MAKE_CREDENTIAL_RESPONSE_AUTH_DATA)
        else {
            panic!("authData should be a byte string");
        };
        assert_eq!(&auth_data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth_data[32], 0x41);
        assert_eq!(&auth_data[33..37], &[0; 4]);
        assert_eq!(&auth_data[37..53], &[0; 16]);
        assert_eq!(u16::from_be_bytes([auth_data[53], auth_data[54]]), 32);
        assert_eq!(&auth_data[55..87], &credential_id);

        let cose_key: Value =
            ciborium::de::from_reader(&auth_data[87..]).expect("COSE key should decode");
        let Value::Map(cose_key) = cose_key else {
            panic!("COSE key should be a map");
        };
        assert_eq!(
            map_value(&cose_key, COSE_KEY_TYPE),
            &Value::Integer(COSE_KEY_TYPE_OKP.into())
        );
        assert_eq!(
            map_value(&cose_key, COSE_KEY_ALGORITHM),
            &Value::Integer(COSE_ALGORITHM_EDDSA.into())
        );
        assert_eq!(
            map_value(&cose_key, COSE_KEY_CURVE),
            &Value::Integer(COSE_CURVE_ED25519.into())
        );
        assert_eq!(
            map_value(&cose_key, COSE_KEY_X_COORDINATE),
            &Value::Bytes(public_key.to_vec())
        );
    }

    #[test]
    fn parses_get_assertion_allow_list_and_silent_probe() {
        let credential_id = vec![0x5a; 32];
        let request = Value::Map(vec![
            (
                Value::Integer(CTAP2_GET_ASSERTION_RP_ID.into()),
                Value::Text("example.com".into()),
            ),
            (
                Value::Integer(CTAP2_GET_ASSERTION_CLIENT_DATA_HASH.into()),
                Value::Bytes(vec![0xa5; 32]),
            ),
            (
                Value::Integer(CTAP2_GET_ASSERTION_ALLOW_LIST.into()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("id".into()),
                        Value::Bytes(credential_id.clone()),
                    ),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])]),
            ),
            (
                Value::Integer(CTAP2_GET_ASSERTION_OPTIONS.into()),
                Value::Map(vec![(Value::Text("up".into()), Value::Bool(false))]),
            ),
        ]);
        let mut payload = vec![ctap2_command::GET_ASSERTION];
        ciborium::ser::into_writer(&request, &mut payload).expect("request should encode");

        let parsed = UhidAuthenticator::parse_get_assertion_request(&payload)
            .expect("request should parse")
            .expect("required parameters should be present");
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.client_data_hash, [0xa5; 32]);
        assert_eq!(parsed.allow_list, vec![credential_id]);
        assert!(!parsed.user_presence);
    }

    #[test]
    fn advertised_hid_capabilities_are_cbor_without_msg() {
        let capabilities = CTAP_HID_CAPABILITY_CBOR | CTAP_HID_CAPABILITY_NMSG;
        assert_eq!(capabilities, 0x0c);
        assert_ne!(capabilities & CTAP_HID_CAPABILITY_CBOR, 0);
        assert_ne!(capabilities & CTAP_HID_CAPABILITY_NMSG, 0);
    }

    #[test]
    fn dummy_u2f_compatibility_response_has_success_status() {
        let response = UhidAuthenticator::dummy_u2f_register_response();
        assert_eq!(response[0], U2F_REGISTER_RESPONSE_RESERVED);
        assert_eq!(&response[response.len() - 2..], &APDU_SW_NO_ERROR);
    }
}
