//! `/partial-decrypt` request authorization. Two shapes:
//!
//! * [`matter_sdk_key::KeySigner`]: an account plus a byte signer (e.g.
//!   [`ApiKey`], an HSM/KMS adapter). [`partial_decrypt_auth`] owns the framing,
//!   so it cannot drift per integration.
//! * [`Signer`]: returns finished auth fields; the implementor owns the framing.
//!   Required for Ethereum/EIP-712, which has no 32-byte account and signs typed
//!   data.
//!
//! [`Sr25519Signer`] is for doctests and demos only.

use matter_sdk_core::signing_payload;
use matter_sdk_core::wire::{to_0x, AuthScheme};
use matter_sdk_key::{AccountId, ApiKey, KeySigner};

use crate::error::Result;

/// SCALE enum index of `MultiSignature::Sr25519` (`Ed25519 = 0`, `Sr25519 = 1`,
/// `Ecdsa = 2`).
const MULTISIGNATURE_SR25519: u8 = 1;

/// Context to authorize one `/partial-decrypt` to one node.
///
/// `recipient_index` is signed so the signature cannot be replayed to another
/// node in the subset. One is built and signed per quorum node.
#[derive(Debug, Clone)]
pub struct SigningRequest<'a> {
    /// The secret being decrypted.
    pub secret_id: u128,
    /// The sorted committee subset being queried.
    pub subset: &'a [u64],
    /// The 1-based `dkg_index` of the node this request is addressed to.
    pub recipient_index: u64,
    /// A recent finalized block hash, the freshness anchor.
    pub block_hash: [u8; 32],
    /// Ethereum path only: block number after which the signature expires.
    pub valid_until: Option<u64>,
}

impl SigningRequest<'_> {
    /// The canonical bytes a Substrate signer signs and the node verifies.
    pub fn payload(&self) -> Vec<u8> {
        signing_payload(
            self.secret_id,
            self.subset,
            &self.block_hash,
            self.recipient_index,
        )
    }
}

/// Auth fields copied unchanged onto a
/// [`matter_sdk_core::wire::PartialDecryptRequest`].
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

/// Authorizes a `/partial-decrypt` request without exposing its key to the SDK.
///
/// Implement this to own the framing (e.g. EIP-712 `PartialDecrypt` with
/// secp256k1). Otherwise implement [`matter_sdk_key::KeySigner`], which also
/// signs extrinsics, and let [`partial_decrypt_auth`] frame it.
pub trait Signer {
    /// The scheme this signer authenticates with.
    fn auth_scheme(&self) -> AuthScheme;

    /// Authorize one request, returning the fields to attach to it.
    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth>;
}

/// Frame a [`KeySigner`]'s signature over `req` as Substrate auth fields: an
/// sr25519 signature over [`SigningRequest::payload`] as a SCALE
/// `MultiSignature`, with the raw `AccountId32` as `requester`. The single
/// implementation of this transcript for all key-backed signers.
pub fn partial_decrypt_auth<S>(signer: &S, req: &SigningRequest<'_>) -> Result<RequestAuth>
where
    S: KeySigner + ?Sized,
{
    let signature = signer.sign(&req.payload())?;

    // SCALE MultiSignature: 1-byte variant index, then the 64-byte signature.
    let mut multisig = Vec::with_capacity(1 + signature.len());
    multisig.push(MULTISIGNATURE_SR25519);
    multisig.extend_from_slice(&signature);

    Ok(RequestAuth {
        auth: AuthScheme::Substrate,
        // SCALE encodes a fixed [u8; 32] verbatim, with no length prefix.
        requester: to_0x(signer.account_id().as_bytes()),
        signature: to_0x(&multisig),
        eth_address: None,
        valid_until: None,
        eth_signature: None,
    })
}

impl Signer for ApiKey {
    fn auth_scheme(&self) -> AuthScheme {
        AuthScheme::Substrate
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        partial_decrypt_auth(self, req)
    }
}

/// An in-memory sr25519 signer. **Examples and tests only.**
///
/// Takes raw key material from an ordinary buffer without [`ApiKey`]'s
/// guarantees (zeroizing, redacted, non-serializable). In production use
/// [`ApiKey`]. See `docs/secure-signing.md`.
pub struct Sr25519Signer {
    key: ApiKey,
}

impl Sr25519Signer {
    /// Build a signer from a raw 32-byte seed. Prints a warning to stderr on
    /// every call.
    pub fn from_seed_insecure_dev_only(seed: &[u8; 32]) -> Result<Self> {
        warn_insecure("from_seed_insecure_dev_only");
        Ok(Self {
            key: ApiKey::from_seed(seed)?,
        })
    }

    /// Build a signer from a `0x` 32-byte hex seed, a BIP39 mnemonic, or a SURI
    /// with derivation junctions. Prints a warning to stderr on every call.
    pub fn from_uri_insecure_dev_only(uri: &str) -> Result<Self> {
        warn_insecure("from_uri_insecure_dev_only");
        Ok(Self {
            key: ApiKey::parse(uri)?,
        })
    }

    /// This signer's 32-byte on-chain `AccountId`.
    pub fn account_id(&self) -> [u8; 32] {
        *self.key.account_id().as_bytes()
    }
}

fn warn_insecure(ctor: &str) {
    eprintln!(
        "WARNING: Sr25519Signer::{ctor} loads a raw private key into memory without \
         the ApiKey container's guarantees. Use ApiKey, or an HSM/KMS-backed \
         KeySigner, in production."
    );
}

impl KeySigner for Sr25519Signer {
    fn scheme(&self) -> matter_sdk_key::KeyScheme {
        self.key.scheme()
    }

    fn account_id(&self) -> AccountId {
        self.key.account_id()
    }

    fn sign(&self, message: &[u8]) -> matter_sdk_key::Result<[u8; 64]> {
        self.key.sign(message)
    }
}

impl Signer for Sr25519Signer {
    fn auth_scheme(&self) -> AuthScheme {
        AuthScheme::Substrate
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        partial_decrypt_auth(&self.key, req)
    }
}

impl<S: Signer + ?Sized> Signer for &S {
    fn auth_scheme(&self) -> AuthScheme {
        (**self).auth_scheme()
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        (**self).authorize(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Substrate dev phrase; same vectors as `matter-sdk-key/tests/parse.rs`.
    const VECTOR_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const VECTOR_SEED_HEX: &str =
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    const VECTOR_ACCOUNT_ID_HEX: &str =
        "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

    fn request(recipient_index: u64) -> SigningRequest<'static> {
        SigningRequest {
            secret_id: 42,
            subset: &[1, 2, 3],
            recipient_index,
            block_hash: [0x11; 32],
            valid_until: None,
        }
    }

    #[test]
    fn substrate_auth_has_canonical_scale_framing() {
        let signer = Sr25519Signer::from_seed_insecure_dev_only(&[7u8; 32]).unwrap();
        let auth = signer.authorize(&request(2)).unwrap();

        assert_eq!(auth.auth, AuthScheme::Substrate);
        // requester = "0x" + 32-byte account.
        let requester = matter_sdk_core::wire::from_0x("requester", &auth.requester).unwrap();
        assert_eq!(requester.len(), 32);
        assert_eq!(requester, signer.account_id());
        // signature = "0x" + 1-byte variant (Sr25519=1) + 64-byte sig.
        let sig = matter_sdk_core::wire::from_0x("signature", &auth.signature).unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(sig[0], MULTISIGNATURE_SR25519);
    }

    #[test]
    fn an_api_key_authorizes_identically_to_the_dev_signer() {
        // sr25519 signatures are randomized; compare the requester.
        let key = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
        let dev = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();

        let from_key = Signer::authorize(&key, &request(1)).unwrap();
        let from_dev = dev.authorize(&request(1)).unwrap();

        assert_eq!(from_key.requester, from_dev.requester);
        assert_eq!(from_key.auth, from_dev.auth);
        assert_eq!(
            hex::encode(key.account_id().as_bytes()),
            VECTOR_ACCOUNT_ID_HEX
        );
    }

    #[test]
    fn signs_the_canonical_payload() {
        let req = SigningRequest {
            secret_id: 9,
            subset: &[2, 4, 6],
            recipient_index: 4,
            block_hash: [0xab; 32],
            valid_until: None,
        };
        assert_eq!(
            req.payload(),
            signing_payload(9, &[2, 4, 6], &[0xab; 32], 4)
        );
    }

    #[test]
    fn per_node_signatures_differ() {
        // A signature made for one node must not be valid at another.
        assert_ne!(request(2).payload(), request(4).payload());
    }

    #[test]
    fn hex_and_mnemonic_uris_derive_the_same_key() {
        let from_mnemonic = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC).unwrap();
        let from_hex = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();
        assert_eq!(
            hex::encode(from_mnemonic.account_id()),
            VECTOR_ACCOUNT_ID_HEX
        );
        assert_eq!(hex::encode(from_hex.account_id()), VECTOR_ACCOUNT_ID_HEX);
    }

    #[test]
    fn from_seed_matches_from_uri_hex() {
        let seed: [u8; 32] = hex::decode(&VECTOR_SEED_HEX[2..])
            .unwrap()
            .try_into()
            .unwrap();
        let from_seed = Sr25519Signer::from_seed_insecure_dev_only(&seed).unwrap();
        let from_uri = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();
        assert_eq!(from_seed.account_id(), from_uri.account_id());
    }

    #[test]
    fn equivalent_encodings_produce_the_same_requester() {
        // sr25519 signatures are randomized; compare the requester.
        let a = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC)
            .unwrap()
            .authorize(&request(1))
            .unwrap();
        let b = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX)
            .unwrap()
            .authorize(&request(1))
            .unwrap();
        assert_eq!(a.requester, b.requester);
    }
}
