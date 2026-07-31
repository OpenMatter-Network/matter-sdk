//! PyO3 binding over the shared Rust cores.
//!
//! Exposes the pure cryptography ([`matter_vault_core`]) and API-key ingestion
//! ([`matter_vault_key`]) to Python, so this binding matches the cross-language
//! fixtures in `testvectors/` byte-for-byte. The committee client, quorum
//! orchestration, and chain client are the pure-Python layer in
//! `python/matter_vault/`.
//!
//! Key *derivation* lives here rather than in `substrate-interface` on purpose.
//! Deriving natively is where this binding drifted: branching on the `0x` prefix
//! routed hex SURIs to `create_from_seed`, which ignores derivation junctions and
//! silently returns the **root** account.

use matter_vault_core as core;
use matter_vault_key::{ApiKey, KeySigner};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Map a core error to a Python `ValueError`.
fn err(e: core::CoreError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Map a key error to a Python `ValueError`. `KeyError` never embeds any part of
/// the key, so its message is safe to surface verbatim.
///
/// Note the name collision: Python's builtin `KeyError` is unrelated, so these
/// surface as `ValueError` to avoid reading like a failed dict lookup.
fn key_err(e: matter_vault_key::KeyError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Seal `plaintext` under `joint_pk`, returning `(binding_id, capsule, proof, ct)`.
#[pyfunction]
#[pyo3(signature = (joint_pk, epoch, plaintext, aad, binding_id=None))]
fn encrypt<'py>(
    py: Python<'py>,
    joint_pk: &[u8],
    epoch: u32,
    plaintext: &[u8],
    aad: &[u8],
    binding_id: Option<Vec<u8>>,
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
)> {
    let env = core::encrypt(joint_pk, epoch, plaintext, aad, binding_id).map_err(err)?;
    Ok((
        PyBytes::new(py, &env.binding_id),
        PyBytes::new(py, &env.capsule),
        PyBytes::new(py, &env.proof),
        PyBytes::new(py, &env.ct),
    ))
}

/// Canonical request signing payload for
/// `(secret_id, subset, block_hash, recipient_index)`. `recipient_index` is the
/// responding node's 1-based `dkg_index` (sign once per node, MV-C1).
#[pyfunction]
fn signing_payload<'py>(
    py: Python<'py>,
    secret_id: u128,
    subset: Vec<u64>,
    block_hash: &[u8],
    recipient_index: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    let bh: [u8; 32] = block_hash
        .try_into()
        .map_err(|_| PyValueError::new_err("block_hash must be 32 bytes"))?;
    Ok(PyBytes::new(
        py,
        &core::signing_payload(secret_id, &subset, &bh, recipient_index),
    ))
}

/// Bincode Lagrange coefficient for `point` over `subset`.
#[pyfunction]
fn lagrange_for<'py>(
    py: Python<'py>,
    point: u64,
    subset: Vec<u64>,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &core::lagrange_for(point, &subset).map_err(err)?,
    ))
}

/// Verify a capsule's ZKPoPlaintext proof up front.
#[pyfunction]
fn verify_plaintext_proof(
    joint_pk: &[u8],
    capsule: &[u8],
    tagged_proof: &[u8],
    binding_id: &[u8],
    epoch: u32,
) -> PyResult<bool> {
    core::verify_plaintext_proof(joint_pk, capsule, tagged_proof, binding_id, epoch).map_err(err)
}

/// Verify the collected quorum, aggregate, and AEAD-open the payload.
///
/// `partials` is a list of `(partial, proof, commitment, lambda)` byte tuples.
/// Returns the recovered plaintext (treat as sensitive — Python has no zeroizing
/// buffer).
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn open_secret<'py>(
    py: Python<'py>,
    shared_a: &[u8],
    capsule: &[u8],
    secret_id: u128,
    epoch: u32,
    binding_id: &[u8],
    aad: &[u8],
    ct: &[u8],
    partials: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> PyResult<Bound<'py, PyBytes>> {
    let inputs: Vec<core::PartialInput> = partials
        .into_iter()
        .map(|(partial, proof, commitment, lambda)| core::PartialInput {
            partial,
            proof,
            commitment,
            lambda,
        })
        .collect();
    let plaintext = core::open_secret(
        shared_a, capsule, secret_id, epoch, binding_id, aad, ct, &inputs,
    )
    .map_err(err)?;
    Ok(PyBytes::new(py, plaintext.expose()))
}

/// An OpenMatter API key: parse once, then sign.
///
/// Derivation and signing happen in Rust, so this agrees byte-for-byte with every
/// other binding on `testvectors/api_keys.json`. The secret never crosses into
/// Python: there is no accessor for it, `repr` is redacted, and pickling and
/// copying are refused.
#[pyclass(name = "ApiKey", module = "matter_vault", frozen)]
struct ApiKeyPy {
    inner: ApiKey,
}

#[pymethods]
impl ApiKeyPy {
    /// Parse a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI
    /// with derivation junctions — each optionally `"sr25519:"`-prefixed.
    ///
    /// Raises `ValueError` for an empty key, an unsupported scheme (`secp256k1:`
    /// is reserved but unimplemented), a malformed encoding, or a failed
    /// derivation. The message never contains key material.
    #[new]
    fn new(key: &str) -> PyResult<Self> {
        Ok(Self {
            inner: ApiKey::parse(key).map_err(key_err)?,
        })
    }

    /// The signature scheme token, e.g. `"sr25519"`.
    #[getter]
    fn scheme(&self) -> &'static str {
        self.inner.scheme().as_str()
    }

    /// The 32-byte on-chain account id this key controls.
    #[getter]
    fn account_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.account_id().as_bytes())
    }

    /// The same account id as `0x` + 64 lowercase hex characters.
    #[getter]
    fn account_id_hex(&self) -> String {
        self.inner.account_id().to_hex()
    }

    /// Sign `message`, returning the raw 64-byte sr25519 signature. Framing
    /// (SCALE `MultiSignature`, extrinsic payload) is the Python layer's job.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let signature = KeySigner::sign(&self.inner, message).map_err(key_err)?;
        Ok(PyBytes::new(py, &signature))
    }

    /// Redacted. Never renders the key.
    fn __repr__(&self) -> String {
        format!(
            "ApiKey({}, {}, <redacted>)",
            self.scheme(),
            self.account_id_hex()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Refuse to pickle. `__reduce__` is how a credential reaches a cache, a
    /// `multiprocessing` queue, or a Celery payload without anyone writing
    /// serialization code.
    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "refusing to pickle an ApiKey; pass the key string through your \
             secret manager instead",
        ))
    }

    /// Refuse to copy, for the same reason: one key, one place to wipe.
    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("refusing to copy an ApiKey"))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err("refusing to deep-copy an ApiKey"))
    }
}

/// The compiled core, imported by the `matter_vault` package as `._native`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(signing_payload, m)?)?;
    m.add_function(wrap_pyfunction!(lagrange_for, m)?)?;
    m.add_function(wrap_pyfunction!(verify_plaintext_proof, m)?)?;
    m.add_function(wrap_pyfunction!(open_secret, m)?)?;
    m.add_class::<ApiKeyPy>()?;
    Ok(())
}
