//! wasm-bindgen binding over [`matter_vault_core`].
//!
//! Exposes the pure cryptographic steps to JS/TS: seal a secret, the canonical
//! request signing payload, the per-node Lagrange coefficient, the up-front proof
//! check, and verify-aggregate-open. Networking, the quorum loop, and signing stay
//! in TypeScript (see `packages/typescript`) — exactly the split the core enforces.
//!
//! Every binary value crosses the boundary as a `Uint8Array`; `secret_id` crosses
//! as a `"0x"`+hex string (JS has no native u128).

use js_sys::Uint8Array;
use matter_vault_core as core;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

/// Install the panic→console hook so Rust panics surface in DevTools.
#[wasm_bindgen(start)]
pub fn _start() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

/// Map a core error to a JS exception.
fn js_err(e: core::CoreError) -> JsError {
    JsError::new(&e.to_string())
}

/// The four-blob sealed envelope returned to JS. Getters return `Uint8Array`
/// directly so each field crosses the boundary with a single copy.
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
/// `joint_pk` is the bincode `PublicKey`; `aad` is the associated data (use a
/// MatterVault AAD tag — see the TS `Aad` enum); `binding_id` defaults to 32
/// random bytes when omitted.
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
/// binding `(secret_id, subset, block_hash)`. `secret_id_hex` / `block_hash_hex`
/// are `"0x"`+hex.
#[wasm_bindgen(js_name = partialDecryptSigningPayload)]
pub fn partial_decrypt_signing_payload(
    secret_id_hex: &str,
    subset: Vec<u64>,
    block_hash_hex: &str,
) -> Result<Uint8Array, JsError> {
    let secret_id = core::wire::secret_id_from_hex(secret_id_hex).map_err(js_err)?;
    let block_hash: [u8; 32] = core::wire::from_0x("block_hash", block_hash_hex)
        .map_err(js_err)?
        .try_into()
        .map_err(|_| JsError::new("block_hash must be 32 bytes"))?;
    Ok(Uint8Array::from(
        &core::signing_payload(secret_id, &subset, &block_hash)[..],
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

/// One collected committee partial, as JS hands it back (all fields bincode bytes
/// as `Uint8Array`).
#[derive(Deserialize)]
pub struct PartialInputJs {
    /// Bincode `PartialDecryption` from the node's response.
    pub partial: Vec<u8>,
    /// Bincode `PartDecProof` from the node's response.
    pub proof: Vec<u8>,
    /// Bincode `FeldmanCommitment` (`g_j`) read from chain.
    pub commitment: Vec<u8>,
    /// Bincode Lagrange `λ` from [`lagrange_for`].
    pub lambda: Vec<u8>,
}

/// Verify the collected quorum's proofs, aggregate, and AEAD-open the payload.
///
/// `secret_id_hex` is `"0x"`+hex; `ct` is `nonce ‖ ciphertext`; `partials` is a JS
/// array of `{ partial, proof, commitment, lambda }`. Returns the recovered
/// plaintext bytes. (JS has no zeroizing buffer; treat the result as sensitive.)
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
            partial: p.partial,
            proof: p.proof,
            commitment: p.commitment,
            lambda: p.lambda,
        })
        .collect();
    let plaintext = core::open_secret(
        shared_a, capsule, secret_id, epoch, binding_id, aad, ct, &partials,
    )
    .map_err(js_err)?;
    Ok(Uint8Array::from(plaintext.expose()))
}
