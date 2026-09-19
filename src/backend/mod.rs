//! Credential key backends used by the authenticator protocol layer.
//!
//! CTAP transports deal only in opaque credential handles, Ed25519 public
//! keys, and Ed25519 signatures. Private key material and signing ceremony
//! details remain inside an implementation of [`CredentialBackend`].

mod local_ed25519;

use std::error::Error;
use std::fmt;

pub use local_ed25519::LocalEd25519Backend;

/// Opaque backend-owned identifier exposed to WebAuthn as a credential ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialHandle(Vec<u8>);

impl CredentialHandle {
    pub fn new(bytes: Vec<u8>) -> Result<Self, BackendError> {
        if bytes.is_empty() {
            return Err(BackendError::InvalidInput(
                "credential handles must not be empty",
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Public result of creating a backend credential.
pub struct CreatedCredential {
    pub handle: CredentialHandle,
    pub public_key: [u8; 32],
}

/// Inputs that bind a newly created key to its WebAuthn credential.
pub struct CreateCredentialRequest<'a> {
    pub rp_id: &'a str,
    pub user_id: &'a [u8],
}

/// Inputs for an assertion signature.
pub struct SignRequest<'a> {
    pub handle: &'a CredentialHandle,
    pub message: &'a [u8],
}

#[derive(Debug)]
pub enum BackendError {
    InvalidInput(&'static str),
    CredentialNotFound,
    Internal(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid backend input: {message}"),
            Self::CredentialNotFound => formatter.write_str("credential not found in backend"),
            Self::Internal(message) => write!(formatter, "credential backend failed: {message}"),
        }
    }
}

impl Error for BackendError {}

/// Backend-neutral credential lifecycle needed by WebAuthn registration and
/// authentication.
pub trait CredentialBackend: Send {
    fn create_credential(
        &mut self,
        request: CreateCredentialRequest<'_>,
    ) -> Result<CreatedCredential, BackendError>;

    fn sign(&mut self, request: SignRequest<'_>) -> Result<[u8; 64], BackendError>;

    fn delete_credential(&mut self, handle: &CredentialHandle) -> Result<(), BackendError>;
}
