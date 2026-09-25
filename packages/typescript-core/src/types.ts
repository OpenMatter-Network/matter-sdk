/** The four-blob envelope an owner publishes on chain for one sealed secret. */
export interface EncryptedSecret {
  /** Caller label bound into the AEAD key derivation and the proof transcript. */
  bindingId: Uint8Array;
  /** Bincode RLWE capsule of the key seed. */
  capsule: Uint8Array;
  /** Version-tagged ZKPoPlaintext proof. */
  proof: Uint8Array;
  /** `nonce(12) ‖ AES-256-GCM ciphertext`. */
  ct: Uint8Array;
}

/** One collected committee partial for {@link openSecret}. Points must be non-zero and distinct. */
export interface PartialInput {
  /** The responding node's 1-based DKG evaluation point (`dkg_index`). */
  point: number;
  /** Bincode `PartialDecryption` from the node response. */
  partial: Uint8Array;
  /** Bincode `PartDecProof` from the node response. */
  proof: Uint8Array;
  /** Bincode `FeldmanCommitment` read from chain, never from the node. */
  commitment: Uint8Array;
}
