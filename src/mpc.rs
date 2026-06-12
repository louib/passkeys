//! Multi-Party Computation (MPC) logic for passkeys.
//!
//! This module defines the traits required for distributed key generation
//! and signing, allowing passkeys to be managed across multiple parties.

use async_trait::async_trait;
use std::error::Error;

/// A trait for parties involved in an MPC ceremony.
///
/// This represents a single node or participant in the computation.
pub trait MpcParticipant {
    /// Returns the unique identifier for this participant.
    fn id(&self) -> &[u8];
}

/// A trait for Multi-Party Key Generation (DKG).
///
/// This is used during the passkey registration phase (`authenticatorMakeCredential`).
#[async_trait]
pub trait MpcKeyGenerator {
    /// The type of public key produced by the MPC ceremony.
    type PublicKey;
    /// The type of credential ID associated with the generated key.
    type CredentialId;

    /// Executes a distributed key generation ceremony.
    ///
    /// # Arguments
    /// * `rp_id` - The Relying Party ID (e.g., "github.com").
    /// * `user_id` - The user identifier provided by the RP.
    async fn generate_key(
        &self,
        rp_id: &str,
        user_id: &[u8],
    ) -> Result<(Self::PublicKey, Self::CredentialId), Box<dyn Error + Send + Sync>>;
}

/// A trait for Multi-Party Signing.
///
/// This is used during the passkey authentication phase (`authenticatorGetAssertion`).
#[async_trait]
pub trait MpcSigner {
    /// The type of signature produced.
    type Signature;

    /// Executes a distributed signing ceremony.
    ///
    /// # Arguments
    /// * `credential_id` - The ID of the credential to sign with.
    /// * `challenge` - The hash of the client data and authenticator data.
    async fn sign(
        &self,
        credential_id: &[u8],
        challenge: &[u8],
    ) -> Result<Self::Signature, Box<dyn Error + Send + Sync>>;
}

/// A combined trait for a full MPC-backed Authenticator Backend.
pub trait MpcBackend: MpcKeyGenerator + MpcSigner {}
impl<T: MpcKeyGenerator + MpcSigner> MpcBackend for T {}
