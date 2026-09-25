//! wasm-bindgen binding over [`matter_sdk_core`] and API-key derivation.
//!
//! Pure crypto only; networking, the quorum loop, and signature framing live in
//! `packages/typescript-core`. Binary values cross as `Uint8Array`; `secret_id`
//! crosses as a `"0x"`+hex string (JS has no native u128).

use js_sys::Uint8Array;
use matter_sdk_core as core;
use matter_sdk_key::{ApiKey, KeyError};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

/// Install the panic→console hook so Rust panics surface in DevTools.
#[wasm_bindgen(start)]
pub fn _start() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

fn js_err(e: core::CoreError) -> JsError {
    JsError::new(&e.to_string())
}

/// Map a key error to a JS exception. `KeyError` never embeds key material.
fn key_err(e: KeyError) -> JsError {
    JsError::new(&e.to_string())
}

/// An OpenMatter API key: parse once, then sign.
///
/// Derivation runs here, not in `@polkadot/util-crypto`, so TS matches every binding on
/// `testvectors/api_keys.json`.
///
/// The secret never crosses into JS: no getter, `toString`/`toJSON` are
/// redacted, and the only outputs are the account id and signatures.
///
/// Call [`ApiKeyJs::free`] (wasm-bindgen generates it) to drop the key and wipe
/// its zeroizing buffers; JS has no destructors.
#[wasm_bindgen(js_name = ApiKey)]
pub struct ApiKeyJs {
    inner: ApiKey,
}

#[wasm_bindgen(js_class = ApiKey)]
impl ApiKeyJs {
    /// Parse a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI,
    /// each optionally prefixed with `"sr25519:"`.
    ///
    /// Throws on an empty key, an unsupported scheme (`secp256k1:` is reserved),
    /// a malformed encoding, or a failed derivation. The message never contains
    /// key material.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &str) -> Result<ApiKeyJs, JsError> {
        Ok(ApiKeyJs {
            inner: ApiKey::parse(key).map_err(key_err)?,
        })
    }

    /// The signature scheme, as a lowercase token (`"sr25519"`).
    #[wasm_bindgen(getter)]
    pub fn scheme(&self) -> String {
        self.inner.scheme().as_str().to_string()
    }

    /// The 32-byte on-chain account id this key controls.
    #[wasm_bindgen(getter, js_name = accountId)]
    pub fn account_id(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.account_id().as_bytes()[..])
    }

    /// The same account id as `0x` + 64 lowercase hex characters.
    #[wasm_bindgen(getter, js_name = accountIdHex)]
    pub fn account_id_hex(&self) -> String {
        self.inner.account_id().to_hex()
    }

    /// Sign `message`, returning the raw 64-byte sr25519 signature (unframed).
    pub fn sign(&self, message: &[u8]) -> Result<Uint8Array, JsError> {
        let signature = self.inner.sign(message).map_err(key_err)?;
        Ok(Uint8Array::from(&signature[..]))
    }

    /// Redacted. Never renders the key.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        format!("ApiKey({}, {}, <redacted>)", self.scheme(), self.account_id_hex())
    }

    /// Redacted: returns the `toString` string, so `JSON.stringify` cannot
    /// serialize key material.
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> String {
        self.to_string_js()
    }
}

/// The four-blob sealed envelope returned to JS.
#[wasm_bindgen]
pub struct EncryptedSecretJs {
    binding_id: Vec<u8>,
    capsule: Vec<u8>,
    proof: Vec<u8>,
    ct: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedSecretJs {
    /// Opaque label bound into the AEAD AAD and key derivation.
    #[wasm_bindgen(getter, js_name = bindingId)]
    pub fn binding_id(&self) -> Uint8Array {
        Uint8Array::from(&self.binding_id[..])
    }
    /// Bincode RLWE capsule of the key seed.
    #[wasm_bindgen(getter)]
    pub fn capsule(&self) -> Uint8Array {
        Uint8Array::from(&self.capsule[..])
    }
    /// Version-tagged ZKPoPlaintext proof.
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Uint8Array {
        Uint8Array::from(&self.proof[..])
    }
    /// `nonce(12) ‖ AES-256-GCM ciphertext`.
    #[wasm_bindgen(getter)]
    pub fn ct(&self) -> Uint8Array {
        Uint8Array::from(&self.ct[..])
    }
}

/// Seal `secrets` under the committee joint public key.
///
/// `joint_pk` is the bincode `PublicKey`; `aad` is the tag's bytes (TS `Aad`);
/// `binding_id` defaults to 32 random bytes.
#[wasm_bindgen(js_name = encryptSecret)]
pub fn encrypt_secret(
    joint_pk: &[u8],
    epoch: u32,
    secrets: &[u8],
    aad: &[u8],
    binding_id: Option<Vec<u8>>,
) -> Result<EncryptedSecretJs, JsError> {
    let env = core::encrypt(joint_pk, epoch, secrets, aad, binding_id).map_err(js_err)?;
    Ok(EncryptedSecretJs {
        binding_id: env.binding_id,
        capsule: env.capsule,
        proof: env.proof,
        ct: env.ct,
    })
}

/// The canonical bytes a requester signs for a `/partial-decrypt` request,
/// binding `(secret_id, subset, block_hash, recipient_index)`. Hex args are
/// `"0x"`+hex; `recipient_index` is the target node's 1-based `dkg_index`, so
/// sign once per node.
#[wasm_bindgen(js_name = partialDecryptSigningPayload)]
pub fn partial_decrypt_signing_payload(
    secret_id_hex: &str,
    subset: Vec<u64>,
    block_hash_hex: &str,
    recipient_index: u64,
) -> Result<Uint8Array, JsError> {
    let secret_id = core::wire::secret_id_from_hex(secret_id_hex).map_err(js_err)?;
    let block_hash: [u8; 32] = core::wire::from_0x("block_hash", block_hash_hex)
        .map_err(js_err)?
        .try_into()
        .map_err(|_| JsError::new("block_hash must be 32 bytes"))?;
    Ok(Uint8Array::from(
        &core::signing_payload(secret_id, &subset, &block_hash, recipient_index)[..],
    ))
}

/// Bincode Lagrange coefficient `λ` for `point` over `subset`.
#[wasm_bindgen(js_name = lagrangeFor)]
pub fn lagrange_for(point: u64, subset: Vec<u64>) -> Result<Uint8Array, JsError> {
    let lambda = core::lagrange_for(point, &subset).map_err(js_err)?;
    Ok(Uint8Array::from(&lambda[..]))
}

/// Verify a capsule's ZKPoPlaintext proof under `joint_pk`, bound to
/// `binding_id` + `epoch`. `tagged_proof` is the version-tagged on-chain blob.
#[wasm_bindgen(js_name = verifyPlaintextProof)]
pub fn verify_plaintext_proof(
    joint_pk: &[u8],
    capsule: &[u8],
    tagged_proof: &[u8],
    binding_id: &[u8],
    epoch: u32,
) -> Result<bool, JsError> {
    core::verify_plaintext_proof(joint_pk, capsule, tagged_proof, binding_id, epoch).map_err(js_err)
}

/// The crypto protocol version this core speaks. A node reporting a different
/// non-zero version in `/health` is dropped from the quorum.
#[wasm_bindgen(js_name = cryptoProtocolVersion)]
pub fn crypto_protocol_version() -> u16 {
    core::CRYPTO_PROTOCOL_VERSION
}

/// The cap on a committee node's response body, in bytes.
#[wasm_bindgen(js_name = maxCommitteeResponseBytes)]
pub fn max_committee_response_bytes() -> f64 {
    core::MAX_COMMITTEE_RESPONSE_BYTES as f64
}

/// One collected committee partial, as passed from JS.
#[derive(Deserialize)]
pub struct PartialInputJs {
    /// The responding node's 1-based DKG evaluation point (`dkg_index`).
    pub point: u64,
    /// Bincode `PartialDecryption` from the node's response.
    pub partial: Vec<u8>,
    /// Bincode `PartDecProof` from the node's response.
    pub proof: Vec<u8>,
    /// Bincode `FeldmanCommitment` (`g_j`) read from chain, never from the node.
    pub commitment: Vec<u8>,
}

/// Verify the collected quorum's proofs, aggregate, and AEAD-open the payload.
///
/// `ct` is `nonce ‖ ciphertext`; `partials` is an array of
/// `{ point, partial, proof, commitment }`. Rejects a zero or repeated point.
/// The core's copy of the plaintext is wiped; the caller must `fill(0)` the
/// returned array when done.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = openSecret)]
pub fn open_secret(
    shared_a: &[u8],
    capsule: &[u8],
    secret_id_hex: &str,
    epoch: u32,
    binding_id: &[u8],
    aad: &[u8],
    ct: &[u8],
    partials: JsValue,
) -> Result<Uint8Array, JsError> {
    let secret_id = core::wire::secret_id_from_hex(secret_id_hex).map_err(js_err)?;
    let inputs: Vec<PartialInputJs> = serde_wasm_bindgen::from_value(partials)
        .map_err(|e| JsError::new(&format!("partials shape: {e}")))?;
    let partials: Vec<core::PartialInput> = inputs
        .into_iter()
        .map(|p| core::PartialInput {
            point: p.point,
            partial: p.partial,
            proof: p.proof,
            commitment: p.commitment,
        })
        .collect();
    let plaintext = core::open_secret(
        shared_a, capsule, secret_id, epoch, binding_id, aad, ct, &partials,
    )
    .map_err(js_err)?;
    Ok(Uint8Array::from(plaintext.expose()))
}
