//! Associated-data (AAD) registry. Opening requires the exact AAD bytes used
//! to seal; use [`Aad`] instead of a byte literal so a typo fails to compile
//! rather than failing AEAD at open time.

/// A versioned, well-known AAD tag used by Secrets flows.
///
/// The bytes are a wire contract with the matter provider. Append-only: mint a
/// new version suffix (`/v2`) rather than editing a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Aad {
    /// Deployment environment variables (`KEY=VALUE` lines).
    EnvV1,
    /// TLS-terminating-proxy configuration.
    TlsV1,
    /// Object-storage credentials for a persistent volume.
    StorageCredsV1,
    /// A persistent-volume data-encryption key (DEK).
    VolumeDekV1,
    /// Dataset data-source credentials (S3 or Postgres) for a data-ingest agent.
    ///
    /// Payload: UTF-8 JSON connector config discriminated by `"kind"`. This is
    /// the canonical schema.
    ///
    /// ```json
    /// { "kind": "s3",
    ///   "bucket_name": "…", "region": "…", "object_key": "…",
    ///   "access_key_id": "…", "secret_access_key": "…" }
    ///
    /// { "kind": "postgres",
    ///   "host": "…", "port": 5432, "database": "…",
    ///   "username": "…", "password": "…",
    ///   "table_name": "…", "ssl_enabled": true }
    /// ```
    ///
    /// Consumers ignore unknown fields; a breaking change mints a `…/v2` tag.
    DatasetSourceCredsV1,
    /// Per-deployment DEK for a QuantumGuard policy envelope. Payload: the raw
    /// 32-byte AES-256-GCM key. The off-chain envelope names this secret id.
    QuantumGuardPolicyDekV1,
}

impl Aad {
    /// The canonical AAD bytes for this tag.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Aad::EnvV1 => b"matter-deployment/env/v1",
            Aad::TlsV1 => b"matter-deployment/tls/v1",
            Aad::StorageCredsV1 => b"matter-volume/storage-creds/v1",
            Aad::VolumeDekV1 => b"matter-volume/dek/v1",
            Aad::DatasetSourceCredsV1 => b"matter-dataset/source-creds/v1",
            Aad::QuantumGuardPolicyDekV1 => b"quantum-guard/policy-dek/v1",
        }
    }
}

impl AsRef<[u8]> for Aad {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_match_the_provider_wire_contract() {
        assert_eq!(Aad::EnvV1.as_bytes(), b"matter-deployment/env/v1");
        assert_eq!(Aad::TlsV1.as_bytes(), b"matter-deployment/tls/v1");
        assert_eq!(
            Aad::StorageCredsV1.as_bytes(),
            b"matter-volume/storage-creds/v1"
        );
        assert_eq!(Aad::VolumeDekV1.as_bytes(), b"matter-volume/dek/v1");
        assert_eq!(
            Aad::DatasetSourceCredsV1.as_bytes(),
            b"matter-dataset/source-creds/v1"
        );
        assert_eq!(
            Aad::QuantumGuardPolicyDekV1.as_bytes(),
            b"quantum-guard/policy-dek/v1"
        );
    }
}
