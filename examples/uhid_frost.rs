use passkeys::backend::FrostBackend;
use passkeys::linux_uhid::UhidAuthenticator;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // MPC POC: participants 1 and 2 sign normally. Participant 3 holds the
    // backup share and can replace either normal participant during recovery.
    let mut backend = FrostBackend::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let participant = if argument == "--unavailable-participant" {
            arguments
                .next()
                .ok_or("--unavailable-participant requires 1, 2, or 3")?
        } else if let Some(value) = argument.strip_prefix("--unavailable-participant=") {
            value.to_owned()
        } else {
            return Err(format!("unknown argument: {argument}").into());
        };
        backend.set_participant_available(participant.parse()?, false)?;
    }

    log::info!("FROST authenticator ready; preferred signers=1+2, automatic fallback=1+3 then 2+3");
    let mut authenticator = UhidAuthenticator::with_backend(Box::new(backend))?;
    authenticator.run()?;

    Ok(())
}
