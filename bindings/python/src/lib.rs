//! PyO3 binding over [`matter_vault_core`].
//!
//! SCAFFOLD — proof-of-binding. Exposes the pure crypto core to Python; the
//! committee client, quorum orchestration, and `Signer` abstraction are tracked
//! in `docs/parity.md`. The functions here call the same core as the Rust and TS
//! SDKs, so they match the cross-language fixtures in `testvectors/`.

use matter_vault_core as core;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Map a core error to a Python `ValueError`.
fn err(e: core::CoreError) -> PyErr {
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

/// The compiled core, imported by the `matter_vault` package as `._native`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(signing_payload, m)?)?;
    m.add_function(wrap_pyfunction!(lagrange_for, m)?)?;
    m.add_function(wrap_pyfunction!(verify_plaintext_proof, m)?)?;
    m.add_function(wrap_pyfunction!(open_secret, m)?)?;
    Ok(())
}
