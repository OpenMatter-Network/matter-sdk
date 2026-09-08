// Associated-data registry — the versioned tags a secret is sealed under and the
// decryptor must present to open it. Use the enum, never a raw string, so a typo
// is a type error rather than a silent decrypt failure. The values are a wire
// contract shared with the provider; treat them as append-only.

export enum Aad {
  EnvV1 = "matter-deployment/env/v1",
  TlsV1 = "matter-deployment/tls/v1",
  StorageCredsV1 = "matter-volume/storage-creds/v1",
  VolumeDekV1 = "matter-volume/dek/v1",
  /** Dataset data-source credentials (S3/Postgres) for the matter-ml agent —
   * payload is the canonical JSON schema in `docs/agent-credential-delivery.md`. */
  DatasetSourceCredsV1 = "matter-dataset/source-creds/v1",
  /** The per-deployment DEK a QuantumGuard policy envelope is sealed under —
   * payload is the raw 32-byte AES-256-GCM key. */
  QuantumGuardPolicyDekV1 = "quantum-guard/policy-dek/v1",
}

const ENCODER = new TextEncoder();

/** The canonical bytes for an AAD tag (or pass through raw bytes). */
export function aadBytes(aad: Aad | Uint8Array): Uint8Array {
  return aad instanceof Uint8Array ? aad : ENCODER.encode(aad);
}
