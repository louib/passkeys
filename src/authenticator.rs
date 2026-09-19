//! Transport-independent WebAuthn credential lifecycle.
//!
//! This layer owns credential metadata and delegates all private-key
//! operations to a [`CredentialBackend`]. HID framing, CTAP encoding, and user
//! interaction belong to transport adapters such as `linux_uhid`.

use crate::backend::{
    BackendError, CreateCredentialRequest, CredentialBackend, CredentialHandle, SignRequest,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

struct CredentialRecord {
    rp_id: String,
    backend_handle: CredentialHandle,
    sign_count: u32,
}

pub struct RegistrationRequest<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
}

pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 32],
}

pub struct AssertionRequest<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8; 32],
    pub allow_list: &'a [Vec<u8>],
    pub user_present: bool,
}

pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: [u8; 64],
    pub sign_count: u32,
}

#[derive(Debug)]
pub enum AuthenticatorError {
    NoCredentials,
    Backend(BackendError),
}

impl fmt::Display for AuthenticatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCredentials => formatter.write_str("no matching credential"),
            Self::Backend(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for AuthenticatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoCredentials => None,
            Self::Backend(error) => Some(error),
        }
    }
}

impl From<BackendError> for AuthenticatorError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

/// Credential and assertion service shared by every CTAP transport.
pub struct AuthenticatorService {
    backend: Box<dyn CredentialBackend>,
    credentials: HashMap<Vec<u8>, CredentialRecord>,
}

impl AuthenticatorService {
    pub fn new(backend: Box<dyn CredentialBackend>) -> Self {
        Self {
            backend,
            credentials: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        request: RegistrationRequest<'_>,
    ) -> Result<Registration, AuthenticatorError> {
        let created = self.backend.create_credential(CreateCredentialRequest {
            rp_id: request.rp_id,
            user_id: request.user_id,
        })?;
        let credential_id = created.handle.as_bytes().to_vec();
        self.credentials.insert(
            credential_id.clone(),
            CredentialRecord {
                rp_id: request.rp_id.to_owned(),
                backend_handle: created.handle,
                sign_count: 0,
            },
        );

        Ok(Registration {
            credential_id,
            public_key: created.public_key,
        })
    }

    pub fn has_matching_credential(&self, rp_id: &str, allow_list: &[Vec<u8>]) -> bool {
        self.select_credential(rp_id, allow_list).is_some()
    }

    pub fn assert(
        &mut self,
        request: AssertionRequest<'_>,
    ) -> Result<Assertion, AuthenticatorError> {
        let credential_id = self
            .select_credential(request.rp_id, request.allow_list)
            .cloned()
            .ok_or(AuthenticatorError::NoCredentials)?;
        let record = self
            .credentials
            .get(&credential_id)
            .expect("selected credential must exist");
        let backend_handle = record.backend_handle.clone();
        let next_sign_count = record.sign_count.saturating_add(1);

        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&Sha256::digest(request.rp_id.as_bytes()));
        authenticator_data.push(u8::from(request.user_present));
        authenticator_data.extend_from_slice(&next_sign_count.to_be_bytes());

        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(request.client_data_hash);
        let signature = self.backend.sign(SignRequest {
            handle: &backend_handle,
            message: &signed_data,
        })?;

        self.credentials
            .get_mut(&credential_id)
            .expect("selected credential must exist")
            .sign_count = next_sign_count;

        Ok(Assertion {
            credential_id,
            authenticator_data,
            signature,
            sign_count: next_sign_count,
        })
    }

    fn select_credential<'a>(&self, rp_id: &str, allow_list: &'a [Vec<u8>]) -> Option<&'a Vec<u8>> {
        allow_list.iter().find(|credential_id| {
            self.credentials
                .get(*credential_id)
                .is_some_and(|credential| credential.rp_id == rp_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalEd25519Backend;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn registration_and_assertion_are_transport_independent() {
        let mut service = AuthenticatorService::new(Box::new(LocalEd25519Backend::default()));
        let registration = service
            .register(RegistrationRequest {
                rp_id: "example.com",
                user_id: b"user-id",
            })
            .unwrap();
        let client_data_hash = [0xa5; 32];
        let assertion = service
            .assert(AssertionRequest {
                rp_id: "example.com",
                client_data_hash: &client_data_hash,
                allow_list: std::slice::from_ref(&registration.credential_id),
                user_present: true,
            })
            .unwrap();

        let mut signed_data = assertion.authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        VerifyingKey::from_bytes(&registration.public_key)
            .unwrap()
            .verify(&signed_data, &Signature::from_bytes(&assertion.signature))
            .unwrap();
        assert_eq!(assertion.sign_count, 1);
    }

    #[test]
    fn credentials_are_bound_to_the_relying_party() {
        let mut service = AuthenticatorService::new(Box::new(LocalEd25519Backend::default()));
        let registration = service
            .register(RegistrationRequest {
                rp_id: "example.com",
                user_id: b"user-id",
            })
            .unwrap();

        assert!(!service.has_matching_credential("other.example", &[registration.credential_id]));
    }
}
