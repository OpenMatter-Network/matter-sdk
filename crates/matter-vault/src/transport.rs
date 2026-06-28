//! The committee HTTP transport.
//!
//! [`Transport`] is the seam between the orchestration logic and the network, so
//! the quorum flow can be tested against a fake committee without a socket.
//! [`ReqwestTransport`] is the production implementation over `reqwest`.

use std::future::Future;

use matter_vault_core::wire::{PartialDecryptRequest, PartialDecryptResponse};
use serde::Deserialize;

use crate::error::{Result, SdkError};

/// A committee node's `/health` response.
#[derive(Debug, Clone, Deserialize)]
pub struct Health {
    /// Node lifecycle status; `"active"` means it can serve partials.
    pub status: String,
    /// The committee's current DKG epoch as this node sees it.
    #[serde(default)]
    pub epoch: u32,
    /// The crypto protocol version this node speaks.
    #[serde(default)]
    pub crypto_protocol_version: u16,
}

impl Health {
    /// Whether this node reports itself ready to serve partial decryptions.
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// How the SDK reaches committee nodes. Implement to test against a fake
/// committee; use [`ReqwestTransport`] in production.
pub trait Transport {
    /// `GET {endpoint}/health`.
    fn health(&self, endpoint: &str) -> impl Future<Output = Result<Health>> + Send;

    /// `POST {endpoint}/partial-decrypt`.
    fn partial_decrypt(
        &self,
        endpoint: &str,
        req: &PartialDecryptRequest,
    ) -> impl Future<Output = Result<PartialDecryptResponse>> + Send;
}

/// The production `reqwest`-backed transport. The caller provides the async
/// runtime (e.g. `tokio`).
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// A transport with default timeouts.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// A transport over a caller-configured `reqwest::Client` (timeouts, TLS
    /// roots, proxies).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// `transport error` helper bound to one endpoint.
    fn err(endpoint: &str, detail: impl std::fmt::Display) -> SdkError {
        SdkError::Transport {
            endpoint: endpoint.to_string(),
            detail: detail.to_string(),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ReqwestTransport {
    async fn health(&self, endpoint: &str) -> Result<Health> {
        let url = format!("{}/health", endpoint.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Self::err(endpoint, e))?
            .error_for_status()
            .map_err(|e| Self::err(endpoint, e))?;
        resp.json::<Health>()
            .await
            .map_err(|e| Self::err(endpoint, e))
    }

    async fn partial_decrypt(
        &self,
        endpoint: &str,
        req: &PartialDecryptRequest,
    ) -> Result<PartialDecryptResponse> {
        let url = format!("{}/partial-decrypt", endpoint.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| Self::err(endpoint, e))?
            .error_for_status()
            .map_err(|e| Self::err(endpoint, e))?;
        resp.json::<PartialDecryptResponse>()
            .await
            .map_err(|e| Self::err(endpoint, e))
    }
}
