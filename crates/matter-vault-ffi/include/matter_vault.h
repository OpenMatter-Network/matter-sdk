/* C ABI for MatterVault — see crates/matter-vault-ffi/src/lib.rs.
 *
 * Ownership: every MvBuf / MvEnvelope returned by this library was allocated by
 * Rust and MUST be released exactly once with mv_free / mv_envelope_free. Input
 * pointers are borrowed for the call only. */
#ifndef MATTER_VAULT_H
#define MATTER_VAULT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MV_OK 0
#define MV_ERR_INVALID_ARG (-1)
#define MV_ERR_CRYPTO (-2)

/* An owned byte buffer. Free with mv_free. */
typedef struct {
  uint8_t *ptr;
  size_t len;
} MvBuf;

/* The four-blob sealed envelope. Free with mv_envelope_free. */
typedef struct {
  MvBuf binding_id;
  MvBuf capsule;
  MvBuf proof;
  MvBuf ct;
} MvEnvelope;

void mv_free(MvBuf buf);
void mv_envelope_free(MvEnvelope env);

/* secret_id: 16 big-endian bytes; block_hash: 32 bytes; subset: subset_len u64s;
 * recipient_index: the responding node's 1-based dkg_index (sign once per node). */
int32_t mv_signing_payload(const uint8_t *secret_id, const uint64_t *subset,
                           size_t subset_len, const uint8_t *block_hash,
                           uint64_t recipient_index, MvBuf *out);

int32_t mv_lagrange_for(uint64_t point, const uint64_t *subset,
                        size_t subset_len, MvBuf *out);

/* binding_id may be NULL (a random one is generated). */
int32_t mv_encrypt(const uint8_t *joint_pk, size_t joint_pk_len, uint32_t epoch,
                   const uint8_t *secrets, size_t secrets_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *binding_id, size_t binding_id_len,
                   MvEnvelope *out);

/* Verify a capsule's plaintext proof; writes 1/0 to *out_valid. */
int32_t mv_verify_plaintext_proof(const uint8_t *joint_pk, size_t joint_pk_len,
                                  const uint8_t *capsule, size_t capsule_len,
                                  const uint8_t *proof, size_t proof_len,
                                  const uint8_t *binding_id, size_t binding_id_len,
                                  uint32_t epoch, uint8_t *out_valid);

/* One collected committee partial, as borrowed input buffers. */
typedef struct {
  const uint8_t *partial;
  size_t partial_len;
  const uint8_t *proof;
  size_t proof_len;
  const uint8_t *commitment;
  size_t commitment_len;
  const uint8_t *lambda;
  size_t lambda_len;
} MvPartialInput;

/* Verify + aggregate + AEAD-open. secret_id is 16 big-endian bytes. Writes the
 * recovered plaintext (a copy the caller owns; sensitive) to *out. */
int32_t mv_open_secret(const uint8_t *shared_a, size_t shared_a_len,
                       const uint8_t *capsule, size_t capsule_len,
                       const uint8_t *secret_id, uint32_t epoch,
                       const uint8_t *binding_id, size_t binding_id_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const MvPartialInput *partials, size_t partials_len,
                       MvBuf *out);

/* ---- API keys -----------------------------------------------------------
 *
 * Key derivation is a cross-language contract (testvectors/api_keys.json), so
 * consumers share this implementation rather than deriving natively. The key
 * material never crosses the boundary: only the account id and signatures do.
 */

/* The key was empty, malformed, or named an unsupported scheme. */
#define MV_ERR_KEY (-3)

/* Opaque handle to a parsed API key. Release with mv_apikey_free. */
typedef struct MvApiKey MvApiKey;

/* Parse UTF-8 key bytes: a 0x mini-secret, a BIP39 mnemonic, or an sr25519
 * SURI, each optionally "sr25519:"-prefixed. On error *out is set to NULL. */
int32_t mv_apikey_parse(const uint8_t *key, size_t key_len, MvApiKey **out);

/* Release a handle, wiping the key material. NULL is a no-op. */
void mv_apikey_free(MvApiKey *key);

/* Write the key's 32-byte account id to *out. */
int32_t mv_apikey_account_id(MvApiKey *key, MvBuf *out);

/* Write the key's scheme token (e.g. "sr25519", UTF-8, no NUL) to *out. */
int32_t mv_apikey_scheme(MvApiKey *key, MvBuf *out);

/* Sign msg, writing the raw 64-byte sr25519 signature (no framing) to *out. */
int32_t mv_apikey_sign(MvApiKey *key, const uint8_t *msg, size_t msg_len, MvBuf *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MATTER_VAULT_H */
