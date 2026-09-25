/**
 * The associated-data tag a secret is sealed under; the decryptor must present the same one.
 * Values are a wire contract with the provider: append-only.
 */
export enum Aad {
  /** Deployment environment variables (`KEY=VALUE` lines). */
  EnvV1 = "matter-deployment/env/v1",
  /** TLS-terminating-proxy configuration. */
  TlsV1 = "matter-deployment/tls/v1",
  /** Object-storage credentials for a persistent volume. */
  StorageCredsV1 = "matter-volume/storage-creds/v1",
  /** A persistent-volume data-encryption key. */
  VolumeDekV1 = "matter-volume/dek/v1",
  /** Dataset data-source credentials (S3/Postgres): UTF-8 JSON with a `"kind"`
   * discriminant; schema on the Rust `Aad::DatasetSourceCredsV1`. */
  DatasetSourceCredsV1 = "matter-dataset/source-creds/v1",
  /** A QuantumGuard per-deployment policy DEK: the raw 32-byte AES-256-GCM key. */
  QuantumGuardPolicyDekV1 = "quantum-guard/policy-dek/v1",
}

const ENCODER = new TextEncoder();

/** The canonical bytes for an AAD tag (or pass through raw bytes). */
export function aadBytes(aad: Aad | Uint8Array): Uint8Array {
  return aad instanceof Uint8Array ? aad : ENCODER.encode(aad);
}
