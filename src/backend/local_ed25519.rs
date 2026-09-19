use super::{
    BackendError, CreateCredentialRequest, CreatedCredential, CredentialBackend, CredentialHandle,
    SignRequest,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::collections::HashMap;

/// In-process backend used as the reference implementation and browser-test
/// baseline. Private keys never leave this type.
#[derive(Default)]
pub struct LocalEd25519Backend {
    keys: HashMap<CredentialHandle, SigningKey>,
}

impl CredentialBackend for LocalEd25519Backend {
    fn create_credential(
        &mut self,
        request: CreateCredentialRequest<'_>,
    ) -> Result<CreatedCredential, BackendError> {
        if request.rp_id.is_empty() {
            return Err(BackendError::InvalidInput("rp.id must not be empty"));
        }

        // The local backend does not need the user ID to derive the key, but
        // accepting it here keeps the boundary suitable for remote/MPC policy.
        let _user_id = request.user_id;
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        let handle = loop {
            let mut bytes = vec![0u8; 32];
            rng.fill_bytes(&mut bytes);
            let handle = CredentialHandle::new(bytes)?;
            if !self.keys.contains_key(&handle) {
                break handle;
            }
        };
        self.keys.insert(handle.clone(), signing_key);

        Ok(CreatedCredential { handle, public_key })
    }

    fn sign(&mut self, request: SignRequest<'_>) -> Result<[u8; 64], BackendError> {
        let signing_key = self
            .keys
            .get(request.handle)
            .ok_or(BackendError::CredentialNotFound)?;
        Ok(signing_key.sign(request.message).to_bytes())
    }

    fn delete_credential(&mut self, handle: &CredentialHandle) -> Result<(), BackendError> {
        self.keys
            .remove(handle)
            .map(|_| ())
            .ok_or(BackendError::CredentialNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn created_credentials_sign_standard_ed25519_messages() {
        let mut backend = LocalEd25519Backend::default();
        let credential = backend
            .create_credential(CreateCredentialRequest {
                rp_id: "example.com",
                user_id: b"user",
            })
            .unwrap();
        let message = b"authenticator data and client data hash";
        let signature = backend
            .sign(SignRequest {
                handle: &credential.handle,
                message,
            })
            .unwrap();

        VerifyingKey::from_bytes(&credential.public_key)
            .unwrap()
            .verify(message, &Signature::from_bytes(&signature))
            .unwrap();
    }

    #[test]
    fn deleted_and_unknown_credentials_cannot_sign() {
        let mut backend = LocalEd25519Backend::default();
        let credential = backend
            .create_credential(CreateCredentialRequest {
                rp_id: "example.com",
                user_id: b"user",
            })
            .unwrap();
        backend.delete_credential(&credential.handle).unwrap();

        assert!(matches!(
            backend.sign(SignRequest {
                handle: &credential.handle,
                message: b"message",
            }),
            Err(BackendError::CredentialNotFound)
        ));
    }
}
