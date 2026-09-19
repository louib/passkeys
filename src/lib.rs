#[cfg(feature = "linux-uhid")]
pub mod linux_uhid;

pub mod authenticator;
pub mod backend;
pub mod ctap_hid;
pub mod mpc;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}
