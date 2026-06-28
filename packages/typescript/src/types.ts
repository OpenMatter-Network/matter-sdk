// Cross-boundary value types for the TS SDK.

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

/** One collected committee partial, ready to hand to {@link openSecret}. */
export interface PartialInput {
  /** Bincode `PartialDecryption` from the node response. */
  partial: Uint8Array;
  /** Bincode `PartDecProof` from the node response. */
  proof: Uint8Array;
  /** Bincode `FeldmanCommitment` read from chain. */
  commitment: Uint8Array;
  /** Bincode Lagrange `λ` for the node over the subset. */
  lambda: Uint8Array;
}
