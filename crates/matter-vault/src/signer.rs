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
///
/// One request targets **one** committee node: `recipient_index` is that node's
/// 1-based `dkg_index`, folded into the signed payload so the signature can't be
/// replayed to another node in the subset (MV-C1). The shell builds and signs one
/// of these per node in the quorum.
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
    /// The canonical bytes a Substrate signer signs — identical to what the
    /// committee node reconstructs and verifies.
    pub fn payload(&self) -> Vec<u8> {
        signing_payload(
            self.secret_id,
            self.subset,
            &self.block_hash,
            self.recipient_index,
        )
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
    /// stderr each time it is constructed.
    pub fn from_seed_insecure_dev_only(seed: &[u8; 32]) -> Result<Self> {
        warn_insecure("from_seed_insecure_dev_only");
        // Straight into the keypair — no `0x{hex}` SecretUri round-trip, which
        // left un-zeroized hex copies of the seed on the heap (MV-M3). This is
        // byte-for-byte the path `Keypair::from_uri` takes for a `0x` phrase.
        let keypair = Keypair::from_secret_key(*seed)
            .map_err(|e| SdkError::Signer(format!("seed: {e}")))?;
        Ok(Self { keypair })
    }

    /// Build a signer from an sr25519 secret URI: a `0x` 32-byte hex seed, a
    /// BIP39 mnemonic, or a full SURI with derivation junctions.
    ///
    /// Same deterrent name and warning as [`Self::from_seed_insecure_dev_only`]:
    /// examples and tests only.
    pub fn from_uri_insecure_dev_only(uri: &str) -> Result<Self> {
        warn_insecure("from_uri_insecure_dev_only");
        let uri =
            SecretUri::from_str(uri).map_err(|e| SdkError::Signer(format!("uri parse: {e}")))?;
        let keypair =
            Keypair::from_uri(&uri).map_err(|e| SdkError::Signer(format!("keypair: {e}")))?;
        Ok(Self { keypair })
    }

    /// This signer's 32-byte sr25519 account id (the on-chain `AccountId`).
    pub fn account_id(&self) -> [u8; 32] {
        self.keypair.public_key().0
    }
}

fn warn_insecure(ctor: &str) {
    eprintln!(
        "WARNING: Sr25519Signer::{ctor} loads a raw private key into memory. \
         Use an HSM/KMS-backed Signer in production."
    );
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
            recipient_index: 2,
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
        // MV-C1: the same (secret, subset, block) signed for two different nodes
        // must produce different signed bytes, so a signature made for one node
        // is not valid at another.
        let base = |recipient_index| SigningRequest {
            secret_id: 9,
            subset: &[2, 4, 6],
            recipient_index,
            block_hash: [0xab; 32],
            valid_until: None,
        };
        assert_ne!(base(2).payload(), base(4).payload());
    }

    // Cross-language seed-format vector — mirrors testvectors/seed_formats.json
    // (kept as consts because inline unit tests shouldn't do file IO; the
    // emit_seed_format_vectors test keeps fixture and consts honest). The same
    // constants are asserted by every language binding and by the dashboard that
    // mints API keys, pinning the key-ingestion contract across repos.
    const VECTOR_MNEMONIC: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const VECTOR_SEED_HEX: &str =
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    const VECTOR_ACCOUNT_ID_HEX: &str =
        "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

    fn vector_account_id() -> [u8; 32] {
        hex::decode(VECTOR_ACCOUNT_ID_HEX)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn hex_and_mnemonic_uris_derive_the_same_key() {
        let from_mnemonic = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC).unwrap();
        let from_hex = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();
        assert_eq!(from_mnemonic.account_id(), vector_account_id());
        assert_eq!(from_hex.account_id(), vector_account_id());
    }

    #[test]
    fn from_seed_matches_from_uri_hex() {
        // Pins the MV-M3 refactor: from_secret_key must stay byte-for-byte the
        // path from_uri takes for a 0x phrase.
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
        // sr25519 signatures are non-deterministic, so compare the requester
        // (account) both constructions attach, not the signature bytes.
        let req = SigningRequest {
            secret_id: 42,
            subset: &[1, 2, 3],
            recipient_index: 1,
            block_hash: [0x22; 32],
            valid_until: None,
        };
        let a = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC)
            .unwrap()
            .authorize(&req)
            .unwrap();
        let b = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX)
            .unwrap()
            .authorize(&req)
            .unwrap();
        assert_eq!(a.requester, b.requester);
    }
}
