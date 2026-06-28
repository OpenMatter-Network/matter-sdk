//! Associated-data (AAD) registry.
//!
//! The AAD is the byte string bound into a secret's AEAD seal; the decryptor
//! must present the *exact same bytes* to open it. The reference dashboard
//! hardcodes these tags as string literals scattered across modules — a drift
//! hazard the SDK removes by giving each a single named home. Prefer [`Aad`]
//! over a raw byte literal so a typo is a compile error, not a silent
//! "AEAD authentication failed" at decrypt time.

/// A versioned, well-known AAD tag used by MatterVault flows.
///
/// The string values are a wire contract shared with the matter provider, which
/// re-derives them when it unseals a secret. Treat them as append-only: bump the
/// version suffix (`/v2`) rather than editing an existing tag.
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
}

impl Aad {
    /// The canonical AAD bytes for this tag.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Aad::EnvV1 => b"matter-deployment/env/v1",
            Aad::TlsV1 => b"matter-deployment/tls/v1",
            Aad::StorageCredsV1 => b"matter-volume/storage-creds/v1",
            Aad::VolumeDekV1 => b"matter-volume/dek/v1",
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
        // These exact strings are re-derived by the provider; a change here is a
        // breaking wire change, so pin them with a test.
        assert_eq!(Aad::EnvV1.as_bytes(), b"matter-deployment/env/v1");
        assert_eq!(Aad::TlsV1.as_bytes(), b"matter-deployment/tls/v1");
        assert_eq!(
            Aad::StorageCredsV1.as_bytes(),
            b"matter-volume/storage-creds/v1"
        );
        assert_eq!(Aad::VolumeDekV1.as_bytes(), b"matter-volume/dek/v1");
    }
}
