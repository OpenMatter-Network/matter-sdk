//! The bring-your-own-signer abstraction.
//!
//! A `/partial-decrypt` request must be signed so the committee can check the
//! requester is authorized for the secret. The SDK never holds your key: you
//! implement [`Signer`] (backed by an HSM, KMS, wallet, or remote signer) and the
//! SDK hands it the canonical bytes to sign. The signer returns the auth fields,
//! which the SDK drops verbatim into the request.
//!
//! [`Sr25519Signer`] is a local, in-memory implementation for **examples and
//! tests only** — see its constructor's name and warning.

use std::str::FromStr;

use matter_vault_core::signing_payload;
use matter_vault_core::wire::{to_0x, AuthScheme};
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

use crate::error::{Result, SdkError};

/// SCALE enum index of `MultiSignature::Sr25519` (`Ed25519 = 0`, `Sr25519 = 1`,
/// `Ecdsa = 2`). The committee verifies `signature` as a SCALE `MultiSignature`.
const MULTISIGNATURE_SR25519: u8 = 1;

/// The per-request context a [`Signer`] needs to authorize one `/partial-decrypt`.
#[derive(Debug, Clone)]
pub struct SigningRequest<'a> {
    /// The secret being decrypted.
    pub secret_id: u128,
    /// The sorted committee subset being queried.
    pub subset: &'a [u64],
    /// A recent finalized block hash, the freshness anchor.
    pub block_hash: [u8; 32],
    /// Ethereum path only: block number after which the signature expires.
    pub valid_until: Option<u64>,
}

impl SigningRequest<'_> {
    /// The canonical bytes a Substrate signer signs — identical to what the
    /// committee node reconstructs and verifies.
    pub fn payload(&self) -> Vec<u8> {
        signing_payload(self.secret_id, self.subset, &self.block_hash)
    }
}

/// The authentication fields a [`Signer`] contributes to a request.
///
/// Field meanings match [`matter_vault_core::wire::PartialDecryptRequest`]; the
/// SDK copies them onto the request unchanged.
#[derive(Debug, Clone)]
pub struct RequestAuth {
    /// Which scheme produced these fields.
    pub auth: AuthScheme,
    /// `0x` + SCALE `AccountId` (Substrate path) or empty (Ethereum path).
    pub requester: String,
    /// `0x` + SCALE `MultiSignature` (Substrate path) or empty (Ethereum path).
    pub signature: String,
    /// Ethereum path: `0x` + 20-byte signer address.
    pub eth_address: Option<String>,
    /// Ethereum path: expiry block number.
    pub valid_until: Option<u64>,
    /// Ethereum path: `0x` + 65-byte secp256k1 signature over the EIP-712 digest.
    pub eth_signature: Option<String>,
}

/// Something that can authorize a `/partial-decrypt` request without exposing its
/// key to the SDK.
///
/// Implement this over your HSM/KMS/wallet. For the Substrate path, sign
/// [`SigningRequest::payload`] with sr25519 and frame the result as
/// [`RequestAuth`] (see [`Sr25519Signer`] for the exact framing). For the
/// Ethereum path, sign the EIP-712 `PartialDecrypt` digest with secp256k1.
pub trait Signer {
    /// The scheme this signer authenticates with.
    fn auth_scheme(&self) -> AuthScheme;

    /// Authorize one request, returning the fields to attach to it.
    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth>;
}

/// A local, in-memory sr25519 signer for the Substrate auth path.
///
/// **For examples and tests only.** It holds raw key material in process memory.
/// Production integrations should implement [`Signer`] over a signer that keeps
/// the key in an HSM, cloud KMS, or hardware wallet — see `docs/secure-signing.md`.
pub struct Sr25519Signer {
    keypair: Keypair,
}

impl Sr25519Signer {
    /// Build a signer from a raw 32-byte seed.
    ///
    /// The name is a deterrent: this loads a private key into process memory and
    /// must never be used in production. It also prints a one-line warning to
    /// stderr the first time it is constructed.
    pub fn from_seed_insecure_dev_only(seed: &[u8; 32]) -> Result<Self> {
        eprintln!(
            "WARNING: Sr25519Signer::from_seed_insecure_dev_only loads a raw \
             private key into memory. Use an HSM/KMS-backed Signer in production."
        );
        let uri = SecretUri::from_str(&format!("0x{}", hex::encode(seed)))
            .map_err(|e| SdkError::Signer(format!("seed parse: {e}")))?;
        let keypair =
            Keypair::from_uri(&uri).map_err(|e| SdkError::Signer(format!("keypair: {e}")))?;
        Ok(Self { keypair })
    }

    /// This signer's 32-byte sr25519 account id (the on-chain `AccountId`).
    pub fn account_id(&self) -> [u8; 32] {
        self.keypair.public_key().0
    }
}

impl Signer for Sr25519Signer {
    fn auth_scheme(&self) -> AuthScheme {
        AuthScheme::Substrate
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        let payload = req.payload();
        let sig = self.keypair.sign(&payload);

        // `requester` is the SCALE-encoded AccountId32 — a fixed [u8; 32], which
        // SCALE encodes verbatim with no length prefix.
        let requester = to_0x(&self.account_id());

        // `signature` is a SCALE-encoded MultiSignature: the 1-byte enum index
        // for the Sr25519 variant followed by the 64-byte signature.
        let mut multisig = Vec::with_capacity(1 + 64);
        multisig.push(MULTISIGNATURE_SR25519);
        multisig.extend_from_slice(&sig.0);

        Ok(RequestAuth {
            auth: AuthScheme::Substrate,
            requester,
            signature: to_0x(&multisig),
            eth_address: None,
            valid_until: None,
            eth_signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_auth_has_canonical_scale_framing() {
        let signer = Sr25519Signer::from_seed_insecure_dev_only(&[7u8; 32]).unwrap();
        let req = SigningRequest {
            secret_id: 42,
            subset: &[1, 2, 3],
            block_hash: [0x11; 32],
            valid_until: None,
        };
        let auth = signer.authorize(&req).unwrap();

        assert_eq!(auth.auth, AuthScheme::Substrate);
        // requester = "0x" + 32-byte account.
        let requester = matter_vault_core::wire::from_0x("requester", &auth.requester).unwrap();
        assert_eq!(requester.len(), 32);
        assert_eq!(requester, signer.account_id());
        // signature = "0x" + 1-byte variant (Sr25519=1) + 64-byte sig.
        let sig = matter_vault_core::wire::from_0x("signature", &auth.signature).unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(sig[0], MULTISIGNATURE_SR25519);
    }

    #[test]
    fn signs_the_canonical_payload() {
        // The bytes signed must equal the shared signing payload, so the node
        // verifies the identical message.
        let req = SigningRequest {
            secret_id: 9,
            subset: &[2, 4, 6],
            block_hash: [0xab; 32],
            valid_until: None,
        };
        assert_eq!(req.payload(), signing_payload(9, &[2, 4, 6], &[0xab; 32]));
    }
}
