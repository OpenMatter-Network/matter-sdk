//! The committee HTTP transport.
//!
//! [`Transport`] is the seam between the orchestration logic and the network, so
//! the quorum flow can be tested against a fake committee without a socket.
//! [`ReqwestTransport`] is the production implementation over `reqwest`.

use std::future::Future;
use std::time::Duration;

use matter_vault_core::wire::{PartialDecryptRequest, PartialDecryptResponse};
use serde::Deserialize;

use crate::error::{Result, SdkError};

/// Whole-request timeout so one stalling node can't hang the sequential quorum
/// flow forever (audit MV-H3). Covers connect + send + body read.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Connection-establishment timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Generous cap on a committee response body — real partials/proofs are a few KB;
/// a larger body is a misbehaving or hostile node, not a real response.
const MAX_RESPONSE_BYTES: usize = 1 << 20; // 1 MiB

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
    /// A transport with conservative default timeouts, so one slow/stalling node
    /// can't hang the quorum. Use [`ReqwestTransport::with_client`] to customize
    /// timeouts, TLS roots, or proxies.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("default reqwest client builds");
        Self { client }
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

    /// Read at most [`MAX_RESPONSE_BYTES`] of the response body, then JSON-decode
    /// it — so a node returning a giant body can't exhaust client memory (the
    /// body cap half of MV-H3; `reqwest`'s `.json()` would buffer it unbounded).
    async fn read_json<T: serde::de::DeserializeOwned>(
        endpoint: &str,
        mut resp: reqwest::Response,
    ) -> Result<T> {
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BYTES as u64 {
                return Err(Self::err(endpoint, format!("response body too large ({len} bytes)")));
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| Self::err(endpoint, e))? {
            if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Self::err(endpoint, "response body exceeded size cap"));
            }
            buf.extend_from_slice(chunk.as_ref());
        }
        serde_json::from_slice::<T>(&buf).map_err(|e| Self::err(endpoint, e))
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
        Self::read_json::<Health>(endpoint, resp).await
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
        Self::read_json::<PartialDecryptResponse>(endpoint, resp).await
    }
}
