use passkeys::linux_uhid::UhidAuthenticator;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Reference implementation: each credential is one local Ed25519 key.
    let mut authenticator = UhidAuthenticator::new()?;
    authenticator.run()?;

    Ok(())
}
