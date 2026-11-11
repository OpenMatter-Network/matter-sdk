//! The OpenMatter Login byte contract.
//!
//! A login is a 32-byte seed sealed under the committee key, owned on chain by
//! the seed's own account, and released only to the holder of a sign-in token
//! for one `(app, issuer, subject)`. The committee node, the chain's
//! `Logins` pallet and every SDK compute the values below independently, so
//! each is a wire contract.
//!
//! This module mirrors `matter_kgc_config::login` (matter-kgc ≥ 0.11) and is
//! pinned by `testvectors/login.json`, whose expectations were computed with
//! an implementation none of the three use: a change needs a new version,
//! never an edit.
//!
//! Nothing here verifies a token or a signature; these are the pure byte
//! constructions around those checks.
//!
//! | Value | What it binds |
//! |---|---|
//! | [`login_identity`] | one person in ONE app |
//! | [`login_nonce`] | a token to the key that will ask |
//! | [`login_payload_hash`] | an attestation to one envelope |
//! | [`login_attestation_payload`] | chain, app, identity, account, envelope, generation |
//! | [`login_seed_aad`] | the sealed seed to its identity |

use crate::error::{CoreError, Result};

/// Bytes of an application id. Opaque; assigned when the app is registered.
pub const APP_ID_BYTES: usize = 32;
/// Bytes of a login identity.
pub const IDENTITY_BYTES: usize = 32;
/// Bytes of an account id, and of the sr25519 public key a token is bound to.
pub const ACCOUNT_BYTES: usize = 32;
/// Bytes of a chain genesis hash.
pub const GENESIS_BYTES: usize = 32;
/// Bytes of a [`login_payload_hash`].
pub const PAYLOAD_HASH_BYTES: usize = 32;
/// Bytes of a login seed.
pub const SEED_BYTES: usize = 32;

/// Domain of [`login_identity`].
pub const IDENTITY_DOMAIN: &[u8] = b"om-login/v1/identity";
/// Domain of [`login_nonce`].
pub const NONCE_DOMAIN: &[u8] = b"om-login/v1/nonce";
/// Domain of [`login_payload_hash`].
pub const PAYLOAD_HASH_DOMAIN: &[u8] = b"om-login/v1/payload";
/// Domain of [`login_attestation_payload`].
pub const ATTESTATION_DOMAIN: &[u8] = b"om-login/v1/attest";
/// Prefix of [`login_seed_aad`].
pub const SEED_AAD_DOMAIN: &[u8] = b"om-login/seed/v1";

/// The generation of a login that has never been rotated.
pub const FIRST_GENERATION: u32 = 0;

/// How old (by its `iat`) a sign-in token may be when a node accepts it.
pub const TOKEN_MAX_AGE_SECS: u64 = 600;
/// Clock skew a node tolerates on `iat` and `exp`.
pub const TOKEN_CLOCK_SKEW_SECS: u64 = 60;

/// Longest issuer (`iss`) or audience (`aud`) an app may register.
pub const MAX_ISSUER_BYTES: usize = 256;
/// Longest subject (`sub`) a node accepts.
pub const MAX_SUBJECT_BYTES: usize = 256;

const DIGEST_BYTES: usize = 32;

/// A fixed-width view of `bytes`, or which field had the wrong length.
fn exact<'a, const N: usize>(field: &'static str, bytes: &'a [u8]) -> Result<&'a [u8; N]> {
    bytes.try_into().map_err(|_| CoreError::InvalidLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

/// A length as four big-endian bytes, so adjacent variable fields cannot be
/// re-split into a different pair with the same concatenation.
fn len_prefix(bytes: &[u8]) -> [u8; 4] {
    // Callers bound every field far below u32::MAX; saturate rather than wrap.
    u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes()
}

/// blake2b-256 of `parts` in order; a `(framed, bytes)` part is hashed behind
/// its [`len_prefix`] when `framed`.
fn digest(parts: &[(bool, &[u8])]) -> [u8; DIGEST_BYTES] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(DIGEST_BYTES)
        .to_state();
    for (framed, bytes) in parts {
        if *framed {
            state.update(&len_prefix(bytes));
        }
        state.update(bytes);
    }
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// Who a login belongs to: `blake2b-256(IDENTITY_DOMAIN ‖ app_id ‖ len(iss) ‖
/// iss ‖ len(sub) ‖ sub)`, lengths as u32 big-endian.
///
/// The app id is inside the hash, so the same person in two apps has two
/// unrelated identities and two unrelated seeds. The audience (`aud`) is NOT
/// part of it: an app may rotate or add client ids without moving anyone.
///
/// * **pre:** `app_id` is 32 bytes; `issuer` and `subject` are the token's
///   `iss` and `sub` claims, byte for byte.
pub fn login_identity(
    app_id: &[u8],
    issuer: &[u8],
    subject: &[u8],
) -> Result<[u8; IDENTITY_BYTES]> {
    let app_id = exact::<APP_ID_BYTES>("app_id", app_id)?;
    Ok(digest(&[
        (false, IDENTITY_DOMAIN),
        (false, app_id),
        (true, issuer),
        (true, subject),
    ]))
}

/// The `nonce` a sign-in token must carry: 64 lowercase hex characters of
/// `blake2b-256(NONCE_DOMAIN ‖ requester)`, where `requester` is the 32-byte
/// sr25519 public key that signs the committee requests. A token minted for
/// one key is useless with any other.
pub fn login_nonce(requester: &[u8]) -> Result<String> {
    let requester = exact::<ACCOUNT_BYTES>("requester", requester)?;
    Ok(hex::encode(digest(&[
        (false, NONCE_DOMAIN),
        (false, requester),
    ])))
}

/// What an attestation says was sealed: `blake2b-256(PAYLOAD_HASH_DOMAIN ‖
/// len(binding_id) ‖ binding_id ‖ len(capsule) ‖ capsule ‖ len(proof) ‖ proof
/// ‖ len(ct) ‖ ct)`, lengths as u32 big-endian.
pub fn login_payload_hash(
    binding_id: &[u8],
    capsule: &[u8],
    proof: &[u8],
    ct: &[u8],
) -> [u8; PAYLOAD_HASH_BYTES] {
    digest(&[
        (false, PAYLOAD_HASH_DOMAIN),
        (true, binding_id),
        (true, capsule),
        (true, proof),
        (true, ct),
    ])
}

/// The bytes a committee node signs to say "a valid token for this identity
/// in this app asked to register this account with this envelope", and the
/// bytes the requester key signs to ask for that. Fixed width:
/// `ATTESTATION_DOMAIN ‖ genesis(32) ‖ app_id(32) ‖ identity(32) ‖ account(32)
/// ‖ payload_hash(32) ‖ generation(u32 BE)`.
///
/// `generation` is [`FIRST_GENERATION`] for a registration, so a registration
/// attestation can never be replayed as a rotation.
pub fn login_attestation_payload(
    genesis: &[u8],
    app_id: &[u8],
    identity: &[u8],
    account: &[u8],
    payload_hash: &[u8],
    generation: u32,
) -> Result<Vec<u8>> {
    let genesis = exact::<GENESIS_BYTES>("genesis", genesis)?;
    let app_id = exact::<APP_ID_BYTES>("app_id", app_id)?;
    let identity = exact::<IDENTITY_BYTES>("identity", identity)?;
    let account = exact::<ACCOUNT_BYTES>("account", account)?;
    let payload_hash = exact::<PAYLOAD_HASH_BYTES>("payload_hash", payload_hash)?;
    Ok([
        ATTESTATION_DOMAIN,
        genesis,
        app_id,
        identity,
        account,
        payload_hash,
        &generation.to_be_bytes(),
    ]
    .concat())
}

/// The AAD a login seed is sealed under: `SEED_AAD_DOMAIN ‖ app_id ‖
/// identity`. A seed envelope cannot be opened as anyone else's, or as any
/// other kind of secret.
pub fn login_seed_aad(app_id: &[u8], identity: &[u8]) -> Result<Vec<u8>> {
    let app_id = exact::<APP_ID_BYTES>("app_id", app_id)?;
    let identity = exact::<IDENTITY_BYTES>("identity", identity)?;
    Ok([SEED_AAD_DOMAIN, app_id, identity].concat())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Domains {
        identity: String,
        nonce: String,
        payload_hash: String,
        attestation: String,
        seed_aad: String,
    }

    #[derive(Deserialize)]
    struct IdentityRow {
        app_id_hex: String,
        issuer: String,
        subject: String,
        identity_hex: String,
    }

    #[derive(Deserialize)]
    struct NonceRow {
        requester_hex: String,
        nonce: String,
    }

    #[derive(Deserialize)]
    struct PayloadRow {
        binding_id_hex: String,
        capsule_hex: String,
        proof_hex: String,
        ct_hex: String,
        payload_hash_hex: String,
    }

    #[derive(Deserialize)]
    struct AttestationRow {
        genesis_hex: String,
        app_id_hex: String,
        identity_hex: String,
        account_hex: String,
        payload_hash_hex: String,
        generation: u32,
        payload_hex: String,
    }

    #[derive(Deserialize)]
    struct AadRow {
        app_id_hex: String,
        identity_hex: String,
        aad_hex: String,
    }

    #[derive(Deserialize)]
    struct Vectors {
        domains: Domains,
        identity: Vec<IdentityRow>,
        nonce: Vec<NonceRow>,
        payload_hash: Vec<PayloadRow>,
        attestation: Vec<AttestationRow>,
        seed_aad: Vec<AadRow>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../../testvectors/login.json"))
            .expect("login.json parses")
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("vector hex")
    }

    #[test]
    fn the_domains_are_the_pinned_ones() {
        let d = vectors().domains;
        assert_eq!(d.identity.as_bytes(), IDENTITY_DOMAIN);
        assert_eq!(d.nonce.as_bytes(), NONCE_DOMAIN);
        assert_eq!(d.payload_hash.as_bytes(), PAYLOAD_HASH_DOMAIN);
        assert_eq!(d.attestation.as_bytes(), ATTESTATION_DOMAIN);
        assert_eq!(d.seed_aad.as_bytes(), SEED_AAD_DOMAIN);
    }

    #[test]
    fn identity_matches_the_vectors() {
        let rows = vectors().identity;
        assert!(rows.len() >= 4, "vector file lost rows");
        for row in rows {
            let got = login_identity(
                &unhex(&row.app_id_hex),
                row.issuer.as_bytes(),
                row.subject.as_bytes(),
            )
            .unwrap();
            assert_eq!(
                hex::encode(got),
                row.identity_hex,
                "iss={} sub={}",
                row.issuer,
                row.subject
            );
        }
    }

    #[test]
    fn nonce_matches_the_vectors() {
        let rows = vectors().nonce;
        assert!(!rows.is_empty());
        for row in rows {
            assert_eq!(login_nonce(&unhex(&row.requester_hex)).unwrap(), row.nonce);
        }
    }

    #[test]
    fn payload_hash_matches_the_vectors() {
        let rows = vectors().payload_hash;
        assert!(!rows.is_empty());
        for row in rows {
            let got = login_payload_hash(
                &unhex(&row.binding_id_hex),
                &unhex(&row.capsule_hex),
                &unhex(&row.proof_hex),
                &unhex(&row.ct_hex),
            );
            assert_eq!(hex::encode(got), row.payload_hash_hex);
        }
    }

    #[test]
    fn attestation_payload_matches_the_vectors() {
        let rows = vectors().attestation;
        assert!(!rows.is_empty());
        for row in rows {
            let got = login_attestation_payload(
                &unhex(&row.genesis_hex),
                &unhex(&row.app_id_hex),
                &unhex(&row.identity_hex),
                &unhex(&row.account_hex),
                &unhex(&row.payload_hash_hex),
                row.generation,
            )
            .unwrap();
            assert_eq!(hex::encode(got), row.payload_hex);
        }
    }

    #[test]
    fn seed_aad_matches_the_vectors() {
        let rows = vectors().seed_aad;
        assert!(!rows.is_empty());
        for row in rows {
            let got = login_seed_aad(&unhex(&row.app_id_hex), &unhex(&row.identity_hex)).unwrap();
            assert_eq!(hex::encode(got), row.aad_hex);
        }
    }

    #[test]
    fn a_wrong_width_input_is_named() {
        let ok = [7u8; 32];
        let short = [7u8; 31];
        let named = |result: Result<Vec<u8>>| match result {
            Err(CoreError::InvalidLength {
                field,
                expected: 32,
                actual: 31,
            }) => field,
            other => panic!("expected InvalidLength, got {other:?}"),
        };
        assert_eq!(
            named(login_identity(&short, b"iss", b"sub").map(Vec::from)),
            "app_id"
        );
        assert_eq!(
            named(login_nonce(&short).map(String::into_bytes)),
            "requester"
        );
        assert_eq!(named(login_seed_aad(&short, &ok)), "app_id");
        assert_eq!(named(login_seed_aad(&ok, &short)), "identity");
        let at = |i: usize| {
            let arg = |n: usize| if n == i { &short[..] } else { &ok[..] };
            login_attestation_payload(arg(0), arg(1), arg(2), arg(3), arg(4), FIRST_GENERATION)
        };
        let fields = ["genesis", "app_id", "identity", "account", "payload_hash"];
        for (i, field) in fields.into_iter().enumerate() {
            assert_eq!(named(at(i)), field);
        }
    }
}
