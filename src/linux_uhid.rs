use soft_fido2::{Authenticator, AuthenticatorConfigBuilder};
use std::error::Error;
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use uhid_virt::{Bus, CreateParams, UHIDDevice};

/// FIDO Alliance Usage Page (0xF1D0).
const USAGE_PAGE_FIDO: u8 = 0xd0;
/// U2F HID Authenticator Usage (0x01).
const USAGE_U2F_AUTHENTICATOR: u8 = 0x01;

/// FIDO2 HID Report Descriptor.
///
/// This descriptor informs the Linux kernel that the virtual device is a FIDO2-compliant
/// security key. It defines two 64-byte raw reports for input and output.
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

/// Default Vendor ID for the virtual MPC token.
pub const DEFAULT_VENDOR_ID: u32 = 0x1234;
/// Default Product ID for the virtual MPC token.
pub const DEFAULT_PRODUCT_ID: u32 = 0x5678;

/// A virtual FIDO2 authenticator that emulates a hardware security key on Linux.
pub struct VirtualAuthenticator {
    device: AsyncFd<UHIDDevice>,
    authenticator: Authenticator,
}

impl VirtualAuthenticator {
    /// Creates a new virtual authenticator.
    ///
    /// This requires access to `/dev/uhid`, which usually requires root privileges
    /// or specific udev rules.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let params = CreateParams {
            name: "MPC Passkey Virtual Token".into(),
            phys: "virt-fido-0".into(),
            uniq: "0001".into(),
            bus: Bus::USB,
            vendor: DEFAULT_VENDOR_ID,
            product: DEFAULT_PRODUCT_ID,
            version: 0,
            country: 0,
            rd_data: FIDO_REPORT_DESC.to_vec(),
        };

        let device = UHIDDevice::create(params)?;
        let async_device = AsyncFd::new(device)?;

        let config = AuthenticatorConfigBuilder::new()
            .with_resident_key_support(true)
            .with_user_verification_support(true)
            .build();

        let authenticator = Authenticator::new(config);

        Ok(Self {
            device: async_device,
            authenticator,
        })
    }

    /// Starts the authenticator loop, processing HID reports from the kernel.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            // Wait for the device to be readable
            let mut guard = self.device.readable().await?;

            // Read the HID event
            match guard.get_inner().read_event() {
                Ok(uhid_virt::OutputEvent::Output { data }) => {
                    // Process the CTAP2 packet through the FIDO2 state machine
                    let responses = self.authenticator.process_packet(&data);

                    // Send responses back to the kernel
                    for resp in responses {
                        guard.get_inner().write_input(&resp)?;
                    }
                }
                Ok(_) => {} // Ignore other events for now
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // This shouldn't happen often with AsyncFd, but we handle it
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
