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
/// Cap on a committee response body.
///
/// This was 1 MiB, on the stated assumption that "real partials/proofs are a few
/// KB". That assumption was wrong: a real `/partial-decrypt` response for a
/// production secret measured **1,180,574 bytes** — over the old cap by ~132 KB —
/// so every honest node's answer was rejected as hostile and no quorum could
/// ever form. Proof size scales with the subset and the BGV parameters, so the
/// true ceiling is not a few KB and should not be guessed at again.
///
/// The cap is the body half of audit finding MV-H3: it stops a misbehaving or
/// hostile node exhausting client memory, since `reqwest`'s `.json()` would
/// buffer without limit. At this value that protection is nominal — a single bad
/// node can make a client buffer up to 1 GiB, which is a quarter of the RAM of a
/// typical guarded deployment's container. It is deliberately set here as an
/// operational choice; a value in the tens of MiB would keep ~15-30x headroom
/// over the observed size while leaving the control meaningful.
///
/// Note this is enforced by growing the buffer and checking as chunks arrive, so
/// a large cap permits growth rather than pre-allocating it.
const MAX_RESPONSE_BYTES: usize = 1 << 30; // 1 GiB

/// A real `/partial-decrypt` response, measured on testnet 2026-09-09.
///
/// Kept as a literal because the number is the whole point: the cap was once set
/// from a guess ("a few KB") that this exceeds by two orders of magnitude, and
/// every honest node's answer was rejected as hostile until it was measured.
const OBSERVED_PARTIAL_BYTES: usize = 1_180_574;

// Guard the cap at COMPILE time, not in a test: a cap too small to admit a real
// response is not a failing assertion somewhere, it is an outage on a provider
// host, and it should be impossible to build.
const _: () = assert!(
    MAX_RESPONSE_BYTES > OBSERVED_PARTIAL_BYTES,
    "MAX_RESPONSE_BYTES rejects a real partial-decrypt response"
);
// Headroom, not a coincidence: proof size scales with the subset and the BGV
// parameters, so a cap that merely clears today's measurement is one parameter
// change away from the same outage.
const _: () = assert!(
    MAX_RESPONSE_BYTES >= OBSERVED_PARTIAL_BYTES * 8,
    "MAX_RESPONSE_BYTES leaves under 8x headroom over a measured response"
);

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
