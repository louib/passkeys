use passkeys::linux_uhid::UhidAuthenticator;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging so we can see the incoming packets
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut authenticator = UhidAuthenticator::new()?;
    authenticator.run()?;

    Ok(())
}
