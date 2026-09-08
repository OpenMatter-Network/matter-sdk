// Pins the AAD registry to the provider wire contract — the same strings the
// Rust core pins in matter-vault-core/src/aad.rs; a change here is a breaking
// wire change.

import { describe, expect, it } from "vitest";

import { Aad, aadBytes } from "../src/aad.js";

describe("Aad registry", () => {
  it("tags match the provider wire contract", () => {
    expect(Aad.EnvV1).toBe("matter-deployment/env/v1");
    expect(Aad.TlsV1).toBe("matter-deployment/tls/v1");
    expect(Aad.StorageCredsV1).toBe("matter-volume/storage-creds/v1");
    expect(Aad.VolumeDekV1).toBe("matter-volume/dek/v1");
    expect(Aad.DatasetSourceCredsV1).toBe("matter-dataset/source-creds/v1");
    expect(Aad.QuantumGuardPolicyDekV1).toBe("quantum-guard/policy-dek/v1");
  });

  it("aadBytes encodes a tag as UTF-8", () => {
    expect(aadBytes(Aad.DatasetSourceCredsV1)).toEqual(
      new TextEncoder().encode("matter-dataset/source-creds/v1"),
    );
  });
});
