/* C ABI for MatterSDK. Contract details: crates/matter-sdk-ffi/src/lib.rs.
 *
 * Every returned MsdkBuf / MsdkEnvelope MUST be released exactly once with
 * msdk_free / msdk_envelope_free, which wipe the bytes first. Inputs are borrowed
 * for the call only; a NULL input is accepted only with a zero length. On error,
 * out-params are left empty. No panic unwinds out: it returns MSDK_ERR_INTERNAL. */
#ifndef MATTER_SDK_H
#define MATTER_SDK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MSDK_OK 0
#define MSDK_ERR_INVALID_ARG (-1)
#define MSDK_ERR_CRYPTO (-2)
/* A caught panic (library bug); retrying will not help. */
#define MSDK_ERR_INTERNAL (-4)

/* An owned byte buffer. Free with msdk_free. */
typedef struct {
  uint8_t *ptr;
  size_t len;
} MsdkBuf;

/* Sealed envelope. Free with msdk_envelope_free. */
typedef struct {
  MsdkBuf binding_id;
  MsdkBuf capsule;
  MsdkBuf proof;
  MsdkBuf ct;
} MsdkEnvelope;

void msdk_free(MsdkBuf buf);
void msdk_envelope_free(MsdkEnvelope env);

/* Crypto protocol version; compare with a node's /health (0 there = not reported). */
int32_t msdk_crypto_protocol_version(void);

/* Cap, in bytes, every transport must enforce on a committee node response body. */
int32_t msdk_max_committee_response_bytes(uint64_t *out);

/* secret_id: 16 big-endian bytes; block_hash: 32 bytes; subset: subset_len u64s;
 * recipient_index: the responding node's 1-based dkg_index (sign once per node). */
int32_t msdk_signing_payload(const uint8_t *secret_id, const uint64_t *subset,
                           size_t subset_len, const uint8_t *block_hash,
                           uint64_t recipient_index, MsdkBuf *out);

int32_t msdk_lagrange_for(uint64_t point, const uint64_t *subset,
                        size_t subset_len, MsdkBuf *out);

/* binding_id may be NULL (a random one is generated). */
int32_t msdk_encrypt(const uint8_t *joint_pk, size_t joint_pk_len, uint32_t epoch,
                   const uint8_t *secrets, size_t secrets_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *binding_id, size_t binding_id_len,
                   MsdkEnvelope *out);

/* Verify a capsule's plaintext proof; writes 1/0 to *out_valid. */
int32_t msdk_verify_plaintext_proof(const uint8_t *joint_pk, size_t joint_pk_len,
                                  const uint8_t *capsule, size_t capsule_len,
                                  const uint8_t *proof, size_t proof_len,
                                  const uint8_t *binding_id, size_t binding_id_len,
                                  uint32_t epoch, uint8_t *out_valid);

/* One committee partial (borrowed). `point` is the node's 1-based dkg_index;
 * coefficients are derived from the points; a zero or repeated point is rejected. */
typedef struct {
  uint64_t point;
  const uint8_t *partial;
  size_t partial_len;
  const uint8_t *proof;
  size_t proof_len;
  const uint8_t *commitment;
  size_t commitment_len;
} MsdkPartialInput;

/* Verify + aggregate + AEAD-open. secret_id: 16 big-endian bytes. *out holds the
 * plaintext: sensitive, wiped by msdk_free. */
int32_t msdk_open_secret(const uint8_t *shared_a, size_t shared_a_len,
                       const uint8_t *capsule, size_t capsule_len,
                       const uint8_t *secret_id, uint32_t epoch,
                       const uint8_t *binding_id, size_t binding_id_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const MsdkPartialInput *partials, size_t partials_len,
                       MsdkBuf *out);

/* ---- API keys ----
 * Key material never crosses the boundary: only the account id and signatures do. */

/* The key was empty, malformed, or named an unsupported scheme. */
#define MSDK_ERR_KEY (-3)

/* Opaque handle to a parsed API key. Release with msdk_apikey_free. */
typedef struct MsdkApiKey MsdkApiKey;

/* Parse UTF-8 key bytes: a 0x mini-secret, a BIP39 mnemonic, or an sr25519
 * SURI, each optionally "sr25519:"-prefixed. On error *out is set to NULL. */
int32_t msdk_apikey_parse(const uint8_t *key, size_t key_len, MsdkApiKey **out);

/* Release a handle, wiping the key material. NULL is a no-op. */
void msdk_apikey_free(MsdkApiKey *key);

/* Write the key's 32-byte account id to *out. */
int32_t msdk_apikey_account_id(MsdkApiKey *key, MsdkBuf *out);

/* Write the key's scheme token (e.g. "sr25519", UTF-8, no NUL) to *out. */
int32_t msdk_apikey_scheme(MsdkApiKey *key, MsdkBuf *out);

/* Sign msg, writing the raw 64-byte sr25519 signature (no framing) to *out. */
int32_t msdk_apikey_sign(MsdkApiKey *key, const uint8_t *msg, size_t msg_len, MsdkBuf *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MATTER_SDK_H */
