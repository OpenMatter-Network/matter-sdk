// Associated-data registry — the versioned tags a secret is sealed under and the
// decryptor must present to open it. Use the enum, never a raw string, so a typo
// is a type error rather than a silent decrypt failure. The values are a wire
// contract shared with the provider; treat them as append-only.

export enum Aad {
  EnvV1 = "matter-deployment/env/v1",
  TlsV1 = "matter-deployment/tls/v1",
  StorageCredsV1 = "matter-volume/storage-creds/v1",
  VolumeDekV1 = "matter-volume/dek/v1",
}

const ENCODER = new TextEncoder();

/** The canonical bytes for an AAD tag (or pass through raw bytes). */
export function aadBytes(aad: Aad | Uint8Array): Uint8Array {
  return aad instanceof Uint8Array ? aad : ENCODER.encode(aad);
}
