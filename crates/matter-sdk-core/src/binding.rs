//! Owner-bound binding ids.
//!
//! A sealed secret's `binding_id` is bound into the capsule's well-formedness
//! proof. An *owner-bound* binding id additionally commits to the account that
//! will own the secret on chain:
//!
//! ```text
//! VERSION (1) ‖ salt (31) ‖ blake2b-256(DOMAIN ‖ VERSION ‖ owner (32) ‖ salt)
//! ```
//!
//! The chain checks that commitment against the account storing the secret, so
//! an envelope sealed with [`crate::seal_for`] is only valid as a secret of
//! that owner. The layout is a wire contract with the chain
//! (`common::config::secrets` in matter-node) pinned by
//! `testvectors/binding_ids.json`: a change needs a new version, never an edit.

use crate::error::{CoreError, Result};

/// Domain separator hashed into an owner-bound binding id.
pub const OWNER_BINDING_DOMAIN: &[u8] = b"matter-secrets/owner-binding/v1";
/// Leading version byte of an owner-bound binding id.
pub const OWNER_BINDING_VERSION: u8 = 0x01;
/// Bytes of the account id an owner-bound binding id commits to.
pub const OWNER_BYTES: usize = 32;
/// Bytes of sealer-chosen salt in an owner-bound binding id.
pub const OWNER_BINDING_SALT_BYTES: usize = 31;
/// Bytes of the commitment hash in an owner-bound binding id.
pub const OWNER_BINDING_HASH_BYTES: usize = 32;
/// Total length of an owner-bound binding id.
pub const OWNER_BINDING_ID_BYTES: usize = 1 + OWNER_BINDING_SALT_BYTES + OWNER_BINDING_HASH_BYTES;

// The form must fit the envelope's on-chain bound exactly.
const _: () =
    assert!(OWNER_BINDING_ID_BYTES == matter_kgc_config::MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE);

fn commitment(owner: &[u8; OWNER_BYTES], salt: &[u8]) -> [u8; OWNER_BINDING_HASH_BYTES] {
    let hash = blake2b_simd::Params::new()
        .hash_length(OWNER_BINDING_HASH_BYTES)
        .to_state()
        .update(OWNER_BINDING_DOMAIN)
        .update(&[OWNER_BINDING_VERSION])
        .update(owner)
        .update(salt)
        .finalize();
    let mut out = [0u8; OWNER_BINDING_HASH_BYTES];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// A fixed-width view of `bytes`, or which field had the wrong length.
fn exact<'a, const N: usize>(field: &'static str, bytes: &'a [u8]) -> Result<&'a [u8; N]> {
    bytes.try_into().map_err(|_| CoreError::InvalidLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

/// The owner-bound binding id for `owner` under `salt`.
///
/// * **pre:** `owner` is the 32-byte account id that will own the secret — the
///   account the store is dispatched as, not necessarily the key that signs
///   it; `salt` is 31 bytes, unique per secret unless you need to recompute
///   the id.
/// * **post:** `binding_commits_to(owner, &id)`.
pub fn binding_id_for(owner: &[u8], salt: &[u8]) -> Result<[u8; OWNER_BINDING_ID_BYTES]> {
    let owner = exact::<OWNER_BYTES>("owner", owner)?;
    let salt = exact::<OWNER_BINDING_SALT_BYTES>("salt", salt)?;
    let mut id = [0u8; OWNER_BINDING_ID_BYTES];
    id[0] = OWNER_BINDING_VERSION;
    id[1..1 + OWNER_BINDING_SALT_BYTES].copy_from_slice(salt);
    id[1 + OWNER_BINDING_SALT_BYTES..].copy_from_slice(&commitment(owner, salt));
    Ok(id)
}

/// Whether `binding_id` is an owner-bound binding id committing to `owner`.
///
/// `false` for anything that is not exactly that: a legacy free-form label, a
/// wrong length, an unknown version, an owner that is not 32 bytes, or another
/// owner's id. A check for *sealers and store calls*; never gate an open on
/// it — secrets sealed before this form existed must keep opening.
pub fn binding_commits_to(owner: &[u8], binding_id: &[u8]) -> bool {
    let (Ok(owner), Ok(id)) = (
        <&[u8; OWNER_BYTES]>::try_from(owner),
        <&[u8; OWNER_BINDING_ID_BYTES]>::try_from(binding_id),
    ) else {
        return false;
    };
    let (version, rest) = id.split_at(1);
    let (salt, hash) = rest.split_at(OWNER_BINDING_SALT_BYTES);
    version == [OWNER_BINDING_VERSION] && hash == commitment(owner, salt)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Commits {
        owner_hex: String,
        salt_hex: String,
        binding_id_hex: String,
    }

    #[derive(Deserialize)]
    struct DoesNotCommit {
        why: String,
        owner_hex: String,
        binding_id_hex: String,
    }

    #[derive(Deserialize)]
    struct Vectors {
        domain: String,
        version: u8,
        commits: Vec<Commits>,
        does_not_commit: Vec<DoesNotCommit>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../../testvectors/binding_ids.json"))
            .expect("binding_ids.json parses")
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("vector hex")
    }

    #[test]
    fn the_constants_are_the_pinned_ones() {
        let v = vectors();
        assert_eq!(v.domain.as_bytes(), OWNER_BINDING_DOMAIN);
        assert_eq!(v.version, OWNER_BINDING_VERSION);
    }

    #[test]
    fn every_pinned_id_is_derived_and_commits() {
        let v = vectors();
        assert!(!v.commits.is_empty());
        for case in v.commits {
            let (owner, salt, id) = (
                unhex(&case.owner_hex),
                unhex(&case.salt_hex),
                unhex(&case.binding_id_hex),
            );
            assert_eq!(binding_id_for(&owner, &salt).unwrap().as_slice(), id);
            assert!(binding_commits_to(&owner, &id));
        }
    }

    #[test]
    fn every_pinned_non_commitment_is_refused() {
        let v = vectors();
        assert!(!v.does_not_commit.is_empty());
        for case in v.does_not_commit {
            assert!(
                !binding_commits_to(&unhex(&case.owner_hex), &unhex(&case.binding_id_hex)),
                "{}",
                case.why
            );
        }
    }

    #[test]
    fn a_wrong_width_input_is_named() {
        let owner = [1u8; OWNER_BYTES];
        let salt = [2u8; OWNER_BINDING_SALT_BYTES];
        assert!(matches!(
            binding_id_for(&owner[..31], &salt),
            Err(CoreError::InvalidLength { field: "owner", expected: 32, actual: 31 })
        ));
        assert!(matches!(
            binding_id_for(&owner, &[2u8; 32]),
            Err(CoreError::InvalidLength { field: "salt", expected: 31, actual: 32 })
        ));
    }
}
