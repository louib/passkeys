use super::{
    BackendError, CreateCredentialRequest, CreatedCredential, CredentialBackend, CredentialHandle,
    SignRequest,
};
use frost::rand_core::OsRng;
use frost_ed25519 as frost;
use log::{info, warn};
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};

const MAX_SIGNERS: u16 = 3;
const MIN_SIGNERS: u16 = 2;
const NORMAL_SIGNERS: [u16; 2] = [1, 2];

struct FrostCredential {
    participants: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: frost::keys::PublicKeyPackage,
}

/// In-process 2-of-3 FROST Ed25519 backend.
///
/// It models three distinct participants and never reconstructs the group
/// secret. The in-memory coordinator is intentionally replaceable by a
/// networked participant implementation in a later milestone.
pub struct FrostBackend {
    credentials: HashMap<CredentialHandle, FrostCredential>,
    preferred_signers: [u16; 2],
    participant_available: [bool; 3],
}

impl Default for FrostBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FrostBackend {
    /// Creates a backend whose normal signing path uses participants 1 and 2.
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            preferred_signers: NORMAL_SIGNERS,
            participant_available: [true; 3],
        }
    }

    /// Creates a backend using a selected pair. `[1, 3]` and `[2, 3]` are the
    /// recovery paths involving the backup participant.
    pub fn with_signing_participants(signing_participants: [u16; 2]) -> Result<Self, BackendError> {
        validate_signers(signing_participants)?;
        Ok(Self {
            credentials: HashMap::new(),
            preferred_signers: signing_participants,
            participant_available: [true; 3],
        })
    }

    pub fn signing_participants(&self) -> [u16; 2] {
        self.preferred_signers
    }

    /// Marks a participant available or unavailable. Signing automatically
    /// selects another valid pair when at least two participants remain.
    pub fn set_participant_available(
        &mut self,
        participant: u16,
        available: bool,
    ) -> Result<(), BackendError> {
        if !(1..=MAX_SIGNERS).contains(&participant) {
            return Err(BackendError::InvalidInput(
                "FROST participant must be numbered 1 through 3",
            ));
        }
        self.participant_available[usize::from(participant - 1)] = available;
        info!(
            "FROST participant {} marked {}",
            participant,
            if available {
                "available"
            } else {
                "unavailable"
            }
        );
        Ok(())
    }

    pub fn selected_signers(&self) -> Result<[u16; 2], BackendError> {
        let candidates = [self.preferred_signers, [1, 2], [1, 3], [2, 3]];
        candidates
            .into_iter()
            .find(|pair| {
                pair.iter()
                    .all(|participant| self.participant_available[usize::from(*participant - 1)])
            })
            .ok_or_else(|| {
                BackendError::Internal(
                    "fewer than two FROST participants are available for signing".into(),
                )
            })
    }

    fn generate_credential() -> Result<FrostCredential, BackendError> {
        info!("FROST DKG starting: threshold=2, participants=3");
        let identifiers = identifiers()?;
        let mut rng = OsRng;

        let mut round1_secrets = BTreeMap::new();
        let mut round1_broadcasts = BTreeMap::new();
        for identifier in identifiers {
            let (secret, package) =
                frost::keys::dkg::part1(identifier, MAX_SIGNERS, MIN_SIGNERS, &mut rng)
                    .map_err(frost_error)?;
            round1_secrets.insert(identifier, secret);
            round1_broadcasts.insert(identifier, package);
        }
        info!("FROST DKG round 1 complete: broadcast commitments collected");

        let mut received_round1 = BTreeMap::new();
        let mut round2_secrets = BTreeMap::new();
        let mut received_round2: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
        for identifier in identifiers {
            let incoming = round1_broadcasts
                .iter()
                .filter(|(sender, _)| **sender != identifier)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect::<BTreeMap<_, _>>();
            let round1_secret = round1_secrets
                .remove(&identifier)
                .ok_or_else(|| BackendError::Internal("missing DKG round-one state".into()))?;
            let (round2_secret, outgoing) =
                frost::keys::dkg::part2(round1_secret, &incoming).map_err(frost_error)?;
            received_round1.insert(identifier, incoming);
            round2_secrets.insert(identifier, round2_secret);
            for (receiver, package) in outgoing {
                received_round2
                    .entry(receiver)
                    .or_default()
                    .insert(identifier, package);
            }
        }
        info!("FROST DKG round 2 complete: peer packages exchanged");

        let mut participants = BTreeMap::new();
        let mut agreed_public_package = None;
        for identifier in identifiers {
            let (key_package, public_package) = frost::keys::dkg::part3(
                round2_secrets
                    .get(&identifier)
                    .ok_or_else(|| BackendError::Internal("missing DKG round-two state".into()))?,
                received_round1.get(&identifier).ok_or_else(|| {
                    BackendError::Internal("missing DKG round-one packages".into())
                })?,
                received_round2.get(&identifier).ok_or_else(|| {
                    BackendError::Internal("missing DKG round-two packages".into())
                })?,
            )
            .map_err(frost_error)?;

            if let Some(expected) = &agreed_public_package {
                if expected != &public_package {
                    return Err(BackendError::Internal(
                        "FROST participants derived different public packages".into(),
                    ));
                }
            } else {
                agreed_public_package = Some(public_package.clone());
            }
            participants.insert(identifier, key_package);
        }

        info!("FROST DKG round 3 complete: all participants agreed on the group key");

        Ok(FrostCredential {
            participants,
            public_key_package: agreed_public_package
                .ok_or_else(|| BackendError::Internal("DKG produced no public package".into()))?,
        })
    }

    fn sign_with(
        credential: &FrostCredential,
        signers: [u16; 2],
        message: &[u8],
    ) -> Result<[u8; 64], BackendError> {
        validate_signers(signers)?;
        info!(
            "FROST signing starting with participants {}+{}",
            signers[0], signers[1]
        );
        let mut rng = OsRng;
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for signer in signers {
            let identifier = frost::Identifier::try_from(signer).map_err(frost_error)?;
            let key_package = credential
                .participants
                .get(&identifier)
                .ok_or_else(|| BackendError::Internal("missing FROST participant".into()))?;
            let (signing_nonces, signing_commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces.insert(identifier, signing_nonces);
            commitments.insert(identifier, signing_commitments);
        }
        info!("FROST signing round 1 complete: fresh commitments collected");

        let signing_package = frost::SigningPackage::new(commitments, message);
        let mut signature_shares = BTreeMap::new();
        for (identifier, signing_nonces) in nonces {
            let key_package = credential
                .participants
                .get(&identifier)
                .ok_or_else(|| BackendError::Internal("missing FROST participant".into()))?;
            let share = frost::round2::sign(&signing_package, &signing_nonces, key_package)
                .map_err(frost_error)?;
            signature_shares.insert(identifier, share);
        }
        info!("FROST signing round 2 complete: signature shares collected");

        let signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &credential.public_key_package,
        )
        .map_err(frost_error)?;
        credential
            .public_key_package
            .verifying_key()
            .verify(message, &signature)
            .map_err(frost_error)?;
        info!("FROST aggregate signature verified against the group public key");
        signature
            .serialize()
            .map_err(frost_error)?
            .try_into()
            .map_err(|_| BackendError::Internal("non-Ed25519 signature length".into()))
    }
}

impl CredentialBackend for FrostBackend {
    fn create_credential(
        &mut self,
        request: CreateCredentialRequest<'_>,
    ) -> Result<CreatedCredential, BackendError> {
        if request.rp_id.is_empty() {
            return Err(BackendError::InvalidInput("rp.id must not be empty"));
        }
        let _user_id = request.user_id;
        info!(
            "Creating FROST credential for rp.id={}, user_id_len={}",
            request.rp_id,
            request.user_id.len()
        );
        let credential = Self::generate_credential()?;
        let public_key = credential
            .public_key_package
            .verifying_key()
            .serialize()
            .map_err(frost_error)?
            .try_into()
            .map_err(|_| BackendError::Internal("non-Ed25519 public key length".into()))?;

        let handle = loop {
            let mut bytes = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let handle = CredentialHandle::new(bytes)?;
            if !self.credentials.contains_key(&handle) {
                break handle;
            }
        };
        self.credentials.insert(handle.clone(), credential);
        info!(
            "FROST credential stored; total_credentials={}",
            self.credentials.len()
        );
        Ok(CreatedCredential { handle, public_key })
    }

    fn sign(&mut self, request: SignRequest<'_>) -> Result<[u8; 64], BackendError> {
        let credential = self
            .credentials
            .get(request.handle)
            .ok_or(BackendError::CredentialNotFound)?;
        let signers = self.selected_signers()?;
        if signers != self.preferred_signers {
            warn!(
                "Preferred FROST participants {}+{} unavailable; automatically using {}+{}",
                self.preferred_signers[0], self.preferred_signers[1], signers[0], signers[1]
            );
        }
        Self::sign_with(credential, signers, request.message)
    }

    fn delete_credential(&mut self, handle: &CredentialHandle) -> Result<(), BackendError> {
        self.credentials
            .remove(handle)
            .map(|_| ())
            .ok_or(BackendError::CredentialNotFound)
    }
}

fn identifiers() -> Result<[frost::Identifier; 3], BackendError> {
    Ok([
        frost::Identifier::try_from(1u16).map_err(frost_error)?,
        frost::Identifier::try_from(2u16).map_err(frost_error)?,
        frost::Identifier::try_from(3u16).map_err(frost_error)?,
    ])
}

fn validate_signers(signers: [u16; 2]) -> Result<(), BackendError> {
    if signers[0] == signers[1]
        || signers
            .iter()
            .any(|signer| !(1..=MAX_SIGNERS).contains(signer))
    {
        return Err(BackendError::InvalidInput(
            "FROST requires two distinct participants numbered 1 through 3",
        ));
    }
    Ok(())
}

fn frost_error(error: impl core::fmt::Debug) -> BackendError {
    BackendError::Internal(format!("FROST error: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn all_two_of_three_pairs_produce_standard_ed25519_signatures() {
        for pair in [[1, 2], [1, 3], [2, 3]] {
            let mut backend = FrostBackend::with_signing_participants(pair).unwrap();
            let credential = backend
                .create_credential(CreateCredentialRequest {
                    rp_id: "example.com",
                    user_id: b"user",
                })
                .unwrap();
            let message = format!("assertion signed by {pair:?}");
            let signature = backend
                .sign(SignRequest {
                    handle: &credential.handle,
                    message: message.as_bytes(),
                })
                .unwrap();

            VerifyingKey::from_bytes(&credential.public_key)
                .unwrap()
                .verify(message.as_bytes(), &Signature::from_bytes(&signature))
                .unwrap();
        }
    }

    #[test]
    fn invalid_signer_sets_are_rejected() {
        assert!(FrostBackend::with_signing_participants([1, 1]).is_err());
        assert!(FrostBackend::with_signing_participants([1, 4]).is_err());
    }

    #[test]
    fn backup_participant_is_selected_automatically() {
        let mut backend = FrostBackend::new();
        assert_eq!(backend.selected_signers().unwrap(), [1, 2]);

        backend.set_participant_available(2, false).unwrap();
        assert_eq!(backend.selected_signers().unwrap(), [1, 3]);

        backend.set_participant_available(2, true).unwrap();
        backend.set_participant_available(1, false).unwrap();
        assert_eq!(backend.selected_signers().unwrap(), [2, 3]);
    }

    #[test]
    fn signing_fails_when_fewer_than_two_participants_are_available() {
        let mut backend = FrostBackend::new();
        backend.set_participant_available(1, false).unwrap();
        backend.set_participant_available(2, false).unwrap();
        assert!(backend.selected_signers().is_err());
    }
}
