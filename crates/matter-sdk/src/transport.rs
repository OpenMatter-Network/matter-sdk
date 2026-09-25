//! Committee HTTP transport. [`Transport`] lets the quorum flow run against a
//! fake committee; [`ReqwestTransport`] is the production implementation.

use std::future::Future;
use std::time::Duration;

use matter_sdk_core::wire::{PartialDecryptRequest, PartialDecryptResponse};
use serde::Deserialize;

use crate::error::{Result, SdkError};

/// Whole-request timeout (connect + send + body) so one stalling node cannot
/// hang the sequential quorum flow.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Shared with every binding so all refuse the same oversized response.
const MAX_RESPONSE_BYTES: usize = matter_sdk_core::MAX_COMMITTEE_RESPONSE_BYTES;

/// A committee node's `/health` response.
#[derive(Debug, Clone, Deserialize)]
pub struct Health {
    /// Node lifecycle status; `"active"` means it can serve partials.
    pub status: String,
    /// The committee's current DKG epoch, as this node sees it.
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

/// Production `reqwest` transport; the caller provides the async runtime.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// A transport with default timeouts (30 s request, 10 s connect). Use
    /// [`ReqwestTransport::with_client`] to customize timeouts, TLS, or proxies.
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

    fn err(endpoint: &str, detail: impl std::fmt::Display) -> SdkError {
        SdkError::Transport {
            endpoint: endpoint.to_string(),
            detail: detail.to_string(),
        }
    }

    /// JSON-decode at most [`MAX_RESPONSE_BYTES`] of the body; `reqwest`'s
    /// `.json()` would buffer an unbounded body.
    async fn read_json<T: serde::de::DeserializeOwned>(
        endpoint: &str,
        mut resp: reqwest::Response,
    ) -> Result<T> {
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BYTES as u64 {
                return Err(Self::err(
                    endpoint,
                    format!("response body too large ({len} bytes)"),
                ));
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
