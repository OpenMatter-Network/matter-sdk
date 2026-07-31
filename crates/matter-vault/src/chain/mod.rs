//! The OpenMatter chain client.
//!
//! Gated behind the `chain` feature, which is **off by default** so the crate's
//! existing dependency graph is preserved for consumers that only need the
//! committee path.
//!
//! # What this gives you
//!
//! One generic, metadata-driven surface that reaches **every** pallet the runtime
//! exposes — 60-plus of them, including ones added by a future forkless upgrade:
//!
//! * [`MatterClient::tx`] — build, sign, and submit any call.
//! * [`MatterClient::query`] — read any storage entry.
//! * [`MatterClient::runtime_api`] — call any runtime API.
//! * [`MatterClient::constant`] — read any pallet constant.
//!
//! Nothing is vendored: pallets and calls resolve by name against the metadata
//! fetched at connect, so this repo never has to track `spec_version`.
//!
//! ```no_run
//! # async fn demo() -> Result<(), matter_vault::SdkError> {
//! use matter_vault::chain::{MatterClient, MatterConfig, Network};
//! use matter_vault::ApiKey;
//! use matter_vault::chain::Value;
//!
//! let key = ApiKey::parse(&std::env::var("MATTER_API_KEY").unwrap())?;
//! let client = MatterClient::connect_with_api_key(
//!     MatterConfig::for_network(Network::Testnet),
//!     key,
//! ).await?;
//!
//! // Read: any storage entry.
//! let account = client
//!     .query("System", "Account", vec![Value::from_bytes(client.account_id().unwrap())])
//!     .await?;
//!
//! // Write: any call, on any pallet.
//! let receipt = client
//!     .tx("Staking", "chill", vec![])
//!     .await?;
//! println!("finalized in {}", receipt.block_hash_hex());
//! # Ok(()) }
//! ```

mod amount;
mod facade;

use std::sync::Arc;
use std::time::Duration;

use matter_vault_key::{AccountId, ApiKey, KeySigner};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::config::DefaultExtrinsicParamsBuilder;
pub use subxt::dynamic::{At, Value};
use subxt::utils::{AccountId32, MultiSignature};
use subxt::{OnlineClient, PolkadotConfig};

pub use self::amount::{format_amount, one_token, parse_amount};
pub use self::facade::{Deployments, Orgs, Resources, Secrets, Staking};
use crate::error::{Result, SdkError};

/// Default RPC endpoint per network.
const TESTNET_RPC: &str = "wss://node2.testnet.openmatter.network";
const MAINNET_RPC: &str = "wss://node1.mainnet.openmatter.network";

/// Genesis hash of the public testnet, read with `chain_getBlockHash(0)` on
/// 2026-07-29. Used to detect which network an endpoint actually serves.
const TESTNET_GENESIS: &str = "d87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058";

/// Token symbols, the fallback network signal while the mainnet genesis hash is
/// unpinned. From `chainspecs/{mainnet,testnet}-spec.json`.
const MAINNET_TOKEN_SYMBOL: &str = "MTR";

/// Environment variable that satisfies the mainnet confirmation guard. Matches
/// the convention the e2e harnesses already use.
const CONFIRM_ENV: &str = "MATTER_CONFIRM";
const CONFIRM_VALUE: &str = "yes";

/// `Balances.ExistentialDeposit` is `UNIT / 1000`, i.e. `10^(decimals - 3)`.
const ED_DECIMAL_OFFSET: u32 = 3;

/// Which OpenMatter network to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Network {
    /// The public testnet. The default.
    Testnet,
    /// Mainnet. Signing clients require explicit confirmation — see
    /// [`MatterConfig::confirm_mainnet`].
    Mainnet,
    /// Anything else (a local dev node, a fork). Requires
    /// [`MatterConfig::rpc_url`]. The mainnet guard still applies if the endpoint
    /// turns out to serve mainnet.
    Custom,
}

impl Network {
    /// The default endpoint, or `None` for [`Network::Custom`].
    pub const fn default_rpc_url(self) -> Option<&'static str> {
        match self {
            Network::Testnet => Some(TESTNET_RPC),
            Network::Mainnet => Some(MAINNET_RPC),
            Network::Custom => None,
        }
    }
}

/// How to connect.
///
/// Build with [`MatterConfig::for_network`] or [`MatterConfig::for_url`] and
/// adjust; the struct is `#[non_exhaustive]` so new knobs are not breaking.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MatterConfig {
    /// Which network. Default [`Network::Testnet`].
    pub network: Network,
    /// Overrides the network's default endpoint. Required for [`Network::Custom`].
    pub rpc_url: Option<String>,
    /// In-code acknowledgement that this client may spend real funds. Also
    /// satisfiable with `MATTER_CONFIRM=yes`. Default `false`.
    pub confirm_mainnet: bool,
    /// How long to wait for a submitted extrinsic to finalize. Default 120s,
    /// matching the Go client's poll budget.
    pub finality_timeout: Duration,
}

impl MatterConfig {
    /// Config for a named network, using its default endpoint.
    pub fn for_network(network: Network) -> Self {
        Self {
            network,
            rpc_url: None,
            confirm_mainnet: false,
            finality_timeout: Duration::from_secs(120),
        }
    }

    /// Config for an explicit endpoint. The network is inferred from the chain's
    /// genesis hash at connect.
    pub fn for_url(url: impl Into<String>) -> Self {
        Self {
            rpc_url: Some(url.into()),
            ..Self::for_network(Network::Custom)
        }
    }

    fn resolve_url(&self) -> Result<String> {
        if let Some(url) = &self.rpc_url {
            return Ok(url.clone());
        }
        self.network
            .default_rpc_url()
            .map(str::to_owned)
            .ok_or_else(|| SdkError::Config {
                detail: "Network::Custom requires MatterConfig::rpc_url".to_string(),
            })
    }
}

impl Default for MatterConfig {
    fn default() -> Self {
        Self::for_network(Network::Testnet)
    }
}

/// Chain identity and unit metadata, read once at connect.
///
/// Both decimal counts are exposed on purpose, because they can disagree.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainProperties {
    /// `chain_getBlockHash(0)`.
    pub genesis_hash: [u8; 32],
    /// `system_chain`, e.g. `"MatterChain Testnet"`.
    pub chain_name: String,
    /// The live runtime's `spec_version`.
    pub spec_version: u32,
    /// `system_properties.tokenSymbol`, e.g. `"MTR-Test"`.
    pub token_symbol: String,
    /// `system_properties.ss58Format`, defaulting to 42.
    pub ss58_prefix: u16,

    /// `system_properties.tokenDecimals` — **presentational**. It is served from
    /// the node's chain-spec file, not the runtime, so it can be stale or ahead
    /// of the deployed wasm. Use it for display parity with explorers; never for
    /// arithmetic.
    pub token_decimals_declared: u8,

    /// Decimals implied by the live runtime's own `Balances.ExistentialDeposit`
    /// constant (`ED == 10^(d-3)`) — **consensus-backed**, and what every SDK
    /// conversion uses.
    ///
    /// This distinction is not academic: matter-node changed `UNIT` from `10^12`
    /// to `10^18` with no storage migration, so a node still serving the old
    /// chain-spec file reports 18 while executing a 12-decimal runtime.
    pub token_decimals_effective: u8,

    /// The raw `Balances.ExistentialDeposit`, in plancks.
    pub existential_deposit: u128,
}

impl ChainProperties {
    /// Whether the node's chain spec disagrees with the runtime it is executing.
    pub fn decimals_disagree(&self) -> bool {
        self.token_decimals_declared != self.token_decimals_effective
    }

    /// Whether this endpoint serves mainnet.
    ///
    /// Genesis hash is the only spoof-resistant signal, but the mainnet hash is
    /// not yet pinned (its RPC was unreachable when this was written), so the
    /// token symbol stands in: mainnet mints `MTR`, testnet `MTR-Test`.
    fn is_mainnet(&self) -> (bool, &'static str) {
        if hex::encode(self.genesis_hash) == TESTNET_GENESIS {
            return (false, "genesis-hash");
        }
        (self.token_symbol == MAINNET_TOKEN_SYMBOL, "token-symbol")
    }
}

/// The outcome of a submitted extrinsic, after finalization.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// Hash of the extrinsic.
    pub tx_hash: [u8; 32],
    /// Hash of the finalized block containing it.
    pub block_hash: [u8; 32],
    /// `(pallet, event)` names emitted by this extrinsic, in order.
    pub events: Vec<(String, String)>,
}

impl TxReceipt {
    /// `0x`-prefixed hex of the finalized block hash.
    pub fn block_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.block_hash))
    }

    /// Whether `pallet.event` was emitted.
    pub fn emitted(&self, pallet: &str, event: &str) -> bool {
        self.events.iter().any(|(p, e)| p == pallet && e == event)
    }
}

/// A client for the OpenMatter chain and the MatterVault committee.
///
/// Four constructors, four distinct intents. There is deliberately no builder:
/// a builder would let you set both an API key and a signer and defer "which
/// wins?" to run time.
pub struct MatterClient {
    api: OnlineClient<PolkadotConfig>,
    rpc: LegacyRpcMethods<PolkadotConfig>,
    signer: Option<Arc<dyn KeySigner>>,
    properties: ChainProperties,
    config: MatterConfig,
}

impl MatterClient {
    /// Connect read-only. Queries work; anything that submits an extrinsic
    /// returns [`SdkError::ReadOnly`].
    pub async fn connect(config: MatterConfig) -> Result<Self> {
        Self::build(config, None).await
    }

    /// Connect with an OpenMatter API key.
    ///
    /// The key is held in process under the guarantees documented on [`ApiKey`].
    /// For production keys in an HSM or KMS, prefer
    /// [`MatterClient::connect_with_signer`] — see `docs/secure-signing.md`.
    pub async fn connect_with_api_key(config: MatterConfig, key: ApiKey) -> Result<Self> {
        Self::build(config, Some(Arc::new(key))).await
    }

    /// Connect with a signer you own — an HSM, a KMS, a remote signing service.
    /// The recommended production path.
    pub async fn connect_with_signer(
        config: MatterConfig,
        signer: Arc<dyn KeySigner>,
    ) -> Result<Self> {
        Self::build(config, Some(signer)).await
    }

    /// Connect from the environment: `MATTER_API_KEY` (falling back to
    /// `MATTER_SIGNER_SEED`, for parity with the e2e harnesses), `MATTER_RPC_URL`,
    /// `MATTER_NETWORK` (`testnet`|`mainnet`), `MATTER_CONFIRM`.
    ///
    /// With no key in the environment this connects read-only rather than
    /// failing, so the same code path serves read-only tooling.
    pub async fn from_env() -> Result<Self> {
        let network = match std::env::var("MATTER_NETWORK").ok().as_deref() {
            Some("mainnet") => Network::Mainnet,
            Some("testnet") | None => Network::Testnet,
            Some(other) => {
                return Err(SdkError::Config {
                    detail: format!("MATTER_NETWORK must be `testnet` or `mainnet`, got `{other}`"),
                })
            }
        };

        let mut config = MatterConfig::for_network(network);
        if let Ok(url) = std::env::var("MATTER_RPC_URL") {
            config.rpc_url = Some(url);
        }

        match env_api_key()? {
            Some(key) => Self::connect_with_api_key(config, key).await,
            None => Self::connect(config).await,
        }
    }

    async fn build(config: MatterConfig, signer: Option<Arc<dyn KeySigner>>) -> Result<Self> {
        let url = config.resolve_url()?;
        let rpc_client = RpcClient::from_url(&url)
            .await
            .map_err(|e| rpc_error(&url, e))?;
        let rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone());
        let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client)
            .await
            .map_err(|e| rpc_error(&url, e))?;

        let properties = read_properties(&api, &rpc).await?;

        let client = Self {
            api,
            rpc,
            signer,
            properties,
            config,
        };
        client.enforce_network_guards()?;
        Ok(client)
    }

    /// Two guards, both about not spending real money by accident.
    ///
    /// The checks are on what the *endpoint* actually serves, not on
    /// `config.network` — pointing `Network::Testnet` at a mainnet URL must still
    /// trip, which is exactly the hole a config-flag check would leave open.
    fn enforce_network_guards(&self) -> Result<()> {
        let (is_mainnet, detected_via) = self.properties.is_mainnet();

        // A typo'd URL should fail before it costs anything.
        if self.config.network == Network::Testnet && is_mainnet {
            return Err(SdkError::WrongNetwork {
                expected: "testnet".to_string(),
                actual: self.properties.chain_name.clone(),
            });
        }

        // Read-only mainnet access needs no confirmation.
        if !is_mainnet || self.signer.is_none() {
            return Ok(());
        }

        let confirmed = self.config.confirm_mainnet
            || std::env::var(CONFIRM_ENV).is_ok_and(|v| v == CONFIRM_VALUE);
        if confirmed {
            return Ok(());
        }
        Err(SdkError::MainnetNotConfirmed {
            chain_name: self.properties.chain_name.clone(),
            detected_via,
        })
    }

    /// Chain identity and unit metadata, read once at connect.
    pub fn properties(&self) -> &ChainProperties {
        &self.properties
    }

    /// The signing identity's account id, or `None` for a read-only client.
    pub fn account_id(&self) -> Option<[u8; 32]> {
        self.signer.as_ref().map(|s| *s.account_id().as_bytes())
    }

    /// The signing identity as a typed account id.
    pub fn account(&self) -> Option<AccountId> {
        self.signer.as_ref().map(|s| s.account_id())
    }

    /// The signing identity's SS58 address, or `None` for a read-only client.
    ///
    /// SS58 rendering lives here rather than on [`AccountId`] because it needs
    /// base58 and blake2b, and `matter-vault-key` is deliberately light enough to
    /// compile into the browser wasm bundle. Here subxt is already paid for.
    ///
    /// Note this uses subxt's default prefix of 42, which is what this chain
    /// reports (`ChainProperties::ss58_prefix`); a chain with a different prefix
    /// would need explicit encoding.
    pub fn address(&self) -> Option<String> {
        self.account_id().map(|id| AccountId32(id).to_string())
    }

    /// The underlying subxt client, for anything this surface does not cover.
    ///
    /// Exposed deliberately: a client that cannot be escaped from is a client
    /// that blocks work. Using it is not a bug report.
    pub fn subxt(&self) -> &OnlineClient<PolkadotConfig> {
        &self.api
    }

    /// The legacy JSON-RPC methods, for `state_call` and friends.
    pub fn rpc(&self) -> &LegacyRpcMethods<PolkadotConfig> {
        &self.rpc
    }

    /// Parse a decimal token amount into plancks, at this chain's effective decimals.
    pub fn parse_amount(&self, text: &str) -> Result<u128> {
        parse_amount(text, self.properties.token_decimals_effective)
    }

    /// Render plancks as a decimal string, at this chain's effective decimals.
    pub fn format_amount(&self, plancks: u128) -> String {
        format_amount(plancks, self.properties.token_decimals_effective)
    }

    /// One whole token in plancks, on this chain.
    pub fn one_token(&self) -> u128 {
        one_token(self.properties.token_decimals_effective)
    }

    // --- The generic surface ------------------------------------------------

    /// Sign and submit `pallet.call(args)`, waiting for finalization.
    ///
    /// Resolution is by name against the live metadata, so this reaches every
    /// pallet the runtime exposes — including ones added after this SDK shipped.
    ///
    /// Waits for **finalization**, not inclusion. That is not a conservative
    /// default: the committee authorizes against the finalized head, so
    /// decrypting a secret stored in a merely-included block returns HTTP 403.
    pub async fn tx(&self, pallet: &str, call: &str, args: Vec<Value>) -> Result<TxReceipt> {
        let signer = self.require_signer()?;
        let payload = subxt::dynamic::tx(pallet, call, args);
        let account = AccountId32(*signer.account_id().as_bytes());

        let mut partial = self
            .api
            .tx()
            .create_partial(
                &payload,
                &account,
                DefaultExtrinsicParamsBuilder::new().build(),
            )
            .await
            .map_err(|e| chain_error(pallet, call, e))?;

        // Sign with our own signer rather than handing subxt a key: the key may
        // live in an HSM, and our `sign` is fallible where subxt's is not.
        let signature = signer.sign(&partial.signer_payload())?;
        let submittable =
            partial.sign_with_account_and_signature(&account, &MultiSignature::Sr25519(signature));

        let in_block = tokio::time::timeout(self.config.finality_timeout, async {
            submittable
                .submit_and_watch()
                .await
                .map_err(|e| chain_error(pallet, call, e))?
                .wait_for_finalized()
                .await
                .map_err(|e| chain_error(pallet, call, e))
        })
        .await
        .map_err(|_| SdkError::FinalityTimeout {
            pallet: pallet.to_string(),
            call: call.to_string(),
            waited: self.config.finality_timeout,
        })??;

        let block_hash = in_block.block_hash().0;
        let tx_hash = in_block.extrinsic_hash().0;

        // `wait_for_success` turns a dispatch error into an `Err`, so a call that
        // landed but failed does not read as success.
        let finalized = in_block
            .wait_for_success()
            .await
            .map_err(|e| chain_error(pallet, call, e))?;

        let events = finalized
            .iter()
            .filter_map(|e| e.ok())
            .map(|e| (e.pallet_name().to_string(), e.variant_name().to_string()))
            .collect();

        Ok(TxReceipt {
            tx_hash,
            block_hash,
            events,
        })
    }

    /// Read a storage entry. `keys` are the map keys, empty for a plain value.
    ///
    /// Returns `None` when the entry is absent, which is normal control flow —
    /// an unfunded account has no `System.Account` entry.
    pub async fn query(
        &self,
        pallet: &str,
        entry: &str,
        keys: Vec<Value>,
    ) -> Result<Option<subxt::dynamic::DecodedValue>> {
        let address = subxt::dynamic::storage(pallet, entry, keys);
        let fetched = self
            .api
            .storage()
            .at_latest()
            .await
            .map_err(|e| chain_error(pallet, entry, e))?
            .fetch(&address)
            .await
            .map_err(|e| chain_error(pallet, entry, e))?;

        match fetched {
            None => Ok(None),
            Some(value) => value
                .to_value()
                .map(Some)
                .map_err(|e| chain_error(pallet, entry, e)),
        }
    }

    /// Call a runtime API, e.g. `runtime_api("KgcApi", "kgc_nodes", vec![])`.
    pub async fn runtime_api(
        &self,
        trait_name: &str,
        method: &str,
        args: Vec<Value>,
    ) -> Result<subxt::dynamic::DecodedValue> {
        let payload = subxt::dynamic::runtime_api_call(trait_name, method, args);
        let value = self
            .api
            .runtime_api()
            .at_latest()
            .await
            .map_err(|e| chain_error(trait_name, method, e))?
            .call(payload)
            .await
            .map_err(|e| chain_error(trait_name, method, e))?;
        value
            .to_value()
            .map_err(|e| chain_error(trait_name, method, e))
    }

    /// Read a pallet constant from the live metadata.
    pub fn constant(&self, pallet: &str, name: &str) -> Result<subxt::dynamic::DecodedValue> {
        let address = subxt::dynamic::constant(pallet, name);
        self.api
            .constants()
            .at(&address)
            .map_err(|e| chain_error(pallet, name, e))?
            .to_value()
            .map_err(|e| chain_error(pallet, name, e))
    }

    // --- curated façades ----------------------------------------------------
    //
    // Accessors rather than fields, so adding a call touches only the façade's own
    // file — never this one, and never `lib.rs`. If a new façade call ever forces a
    // change to `SdkError` or `MatterConfig`, the seam has leaked; treat that as a
    // design bug, not a routine edit.

    /// Secrets: store, rotate, share, and delete MatterVault secrets.
    pub fn secrets(&self) -> Secrets<'_> {
        Secrets(self)
    }

    /// Deployments (`pallet-jobs`): request compute, wire networking, bind secrets.
    pub fn deployments(&self) -> Deployments<'_> {
        Deployments(self)
    }

    /// Resources: register capacity, price it, control who may use it.
    pub fn resources(&self) -> Resources<'_> {
        Resources(self)
    }

    /// Staking on MatterChain, including nomination pools.
    pub fn staking(&self) -> Staking<'_> {
        Staking(self)
    }

    /// Organizations and budgets.
    pub fn orgs(&self) -> Orgs<'_> {
        Orgs(self)
    }

    fn require_signer(&self) -> Result<&Arc<dyn KeySigner>> {
        self.signer.as_ref().ok_or(SdkError::ReadOnly)
    }
}

/// Read `MATTER_API_KEY`, falling back to `MATTER_SIGNER_SEED` for parity with
/// the existing e2e harnesses.
fn env_api_key() -> Result<Option<ApiKey>> {
    for var in ["MATTER_API_KEY", "MATTER_SIGNER_SEED"] {
        match std::env::var(var) {
            Ok(value) if !value.trim().is_empty() => return Ok(Some(ApiKey::parse(&value)?)),
            _ => continue,
        }
    }
    Ok(None)
}

async fn read_properties(
    api: &OnlineClient<PolkadotConfig>,
    rpc: &LegacyRpcMethods<PolkadotConfig>,
) -> Result<ChainProperties> {
    let chain_name = rpc
        .system_chain()
        .await
        .map_err(|e| rpc_error("system_chain", e))?;
    let props = rpc
        .system_properties()
        .await
        .map_err(|e| rpc_error("system_properties", e))?;

    let token_symbol = props
        .get("tokenSymbol")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let token_decimals_declared = props
        .get("tokenDecimals")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let ss58_prefix = props
        .get("ss58Format")
        .and_then(|v| v.as_u64())
        .unwrap_or(42) as u16;

    // The consensus-backed decimal count: ED == 10^(decimals - 3).
    let existential_deposit = read_existential_deposit(api)?;
    let token_decimals_effective =
        decimals_from_existential_deposit(existential_deposit).unwrap_or(token_decimals_declared);

    let properties = ChainProperties {
        genesis_hash: api.genesis_hash().0,
        chain_name,
        spec_version: api.runtime_version().spec_version,
        token_symbol,
        ss58_prefix,
        token_decimals_declared,
        token_decimals_effective,
        existential_deposit,
    };

    if properties.decimals_disagree() {
        // Loud once, then trust the runtime. Quiet success, loud surprise.
        eprintln!(
            "WARNING: {} reports tokenDecimals={} in its chain spec but is executing a \
             runtime whose ExistentialDeposit implies {}. Using {} for all arithmetic.",
            properties.chain_name,
            properties.token_decimals_declared,
            properties.token_decimals_effective,
            properties.token_decimals_effective,
        );
    }
    Ok(properties)
}

fn read_existential_deposit(api: &OnlineClient<PolkadotConfig>) -> Result<u128> {
    let address = subxt::dynamic::constant("Balances", "ExistentialDeposit");
    let value = api
        .constants()
        .at(&address)
        .map_err(|e| chain_error("Balances", "ExistentialDeposit", e))?
        .to_value()
        .map_err(|e| chain_error("Balances", "ExistentialDeposit", e))?;
    value.as_u128().ok_or_else(|| SdkError::Chain {
        target: "Balances.ExistentialDeposit".to_string(),
        detail: "constant is not an unsigned integer".to_string(),
    })
}

/// Recover the decimal count from `ED == 10^(d - 3)`, or `None` if the constant
/// is not a clean power of ten (a runtime that changed the ED policy).
fn decimals_from_existential_deposit(ed: u128) -> Option<u8> {
    let mut value = ed;
    let mut exponent = 0u32;
    while value > 1 && value.is_multiple_of(10) {
        value /= 10;
        exponent += 1;
    }
    (value == 1).then(|| (exponent + ED_DECIMAL_OFFSET) as u8)
}

fn rpc_error(target: &str, e: impl std::fmt::Display) -> SdkError {
    SdkError::Chain {
        target: target.to_string(),
        detail: e.to_string(),
    }
}

fn chain_error(pallet: &str, item: &str, e: impl std::fmt::Display) -> SdkError {
    SdkError::Chain {
        target: format!("{pallet}.{item}"),
        detail: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existential_deposit_implies_the_documented_decimal_counts() {
        // The two runtimes that exist: pre-8351fec (UNIT = 10^12) and current
        // (10^18). Both must be recognised without a network.
        assert_eq!(decimals_from_existential_deposit(10u128.pow(15)), Some(18));
        assert_eq!(decimals_from_existential_deposit(10u128.pow(9)), Some(12));
        assert_eq!(decimals_from_existential_deposit(1), Some(3));
        // A non-power-of-ten ED means the policy changed; fall back rather than
        // reporting a confidently wrong exponent.
        assert_eq!(decimals_from_existential_deposit(0), None);
        assert_eq!(decimals_from_existential_deposit(1_500), None);
    }

    #[test]
    fn custom_network_requires_an_explicit_url() {
        let config = MatterConfig::for_network(Network::Custom);
        assert!(config.resolve_url().is_err());

        let config = MatterConfig::for_url("ws://127.0.0.1:9944");
        assert_eq!(config.resolve_url().unwrap(), "ws://127.0.0.1:9944");
    }

    #[test]
    fn named_networks_have_default_endpoints() {
        assert_eq!(
            MatterConfig::for_network(Network::Testnet)
                .resolve_url()
                .unwrap(),
            TESTNET_RPC
        );
        assert_eq!(
            MatterConfig::for_network(Network::Mainnet)
                .resolve_url()
                .unwrap(),
            MAINNET_RPC
        );
    }

    #[test]
    fn the_default_config_is_testnet_and_unconfirmed() {
        // Defaults should read as obviously safe: a fresh config cannot spend
        // real funds.
        let config = MatterConfig::default();
        assert_eq!(config.network, Network::Testnet);
        assert!(!config.confirm_mainnet);
    }

    fn properties(symbol: &str, genesis: [u8; 32]) -> ChainProperties {
        ChainProperties {
            genesis_hash: genesis,
            chain_name: "MatterChain".to_string(),
            spec_version: 308,
            token_symbol: symbol.to_string(),
            ss58_prefix: 42,
            token_decimals_declared: 18,
            token_decimals_effective: 18,
            existential_deposit: 10u128.pow(15),
        }
    }

    #[test]
    fn the_pinned_testnet_genesis_is_recognised_as_not_mainnet() {
        let mut genesis = [0u8; 32];
        hex::decode_to_slice(TESTNET_GENESIS, &mut genesis).unwrap();
        // Even with mainnet's token symbol, the genesis hash wins.
        let (is_mainnet, via) = properties(MAINNET_TOKEN_SYMBOL, genesis).is_mainnet();
        assert!(!is_mainnet);
        assert_eq!(via, "genesis-hash");
    }

    #[test]
    fn an_unknown_chain_falls_back_to_the_token_symbol() {
        let (is_mainnet, via) = properties("MTR", [0xab; 32]).is_mainnet();
        assert!(is_mainnet);
        assert_eq!(via, "token-symbol");

        let (is_mainnet, _) = properties("MTR-Test", [0xab; 32]).is_mainnet();
        assert!(!is_mainnet);
    }

    #[test]
    fn decimals_disagreement_is_detectable() {
        let mut props = properties("MTR-Test", [0u8; 32]);
        assert!(!props.decimals_disagree());
        props.token_decimals_effective = 12;
        assert!(props.decimals_disagree());
    }

    #[test]
    fn a_receipt_reports_which_events_fired() {
        let receipt = TxReceipt {
            tx_hash: [1u8; 32],
            block_hash: [2u8; 32],
            events: vec![
                ("Secrets".to_string(), "SecretStored".to_string()),
                ("System".to_string(), "ExtrinsicSuccess".to_string()),
            ],
        };
        assert!(receipt.emitted("Secrets", "SecretStored"));
        assert!(!receipt.emitted("Secrets", "SecretDeleted"));
        assert!(receipt.block_hash_hex().starts_with("0x0202"));
    }
}
