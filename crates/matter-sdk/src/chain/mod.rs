//! The MatterChain client (`chain` feature, off by default).
//!
//! A metadata-driven surface over every pallet; names resolve against metadata
//! fetched at connect:
//!
//! * [`MatterClient::tx`]: build, sign, and submit any call.
//! * [`MatterClient::query`]: read any storage entry.
//! * [`MatterClient::runtime_api`]: call any runtime API.
//! * [`MatterClient::constant`]: read any pallet constant.
//!
//! ```no_run
//! # async fn demo() -> Result<(), matter_sdk::SdkError> {
//! use matter_sdk::chain::{MatterClient, MatterConfig, Network};
//! use matter_sdk::ApiKey;
//! use matter_sdk::chain::Value;
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
mod mode;
mod recover;
pub mod scopes_table;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use matter_sdk_key::{AccountId, ApiKey, KeySigner, ScopeSet};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::config::DefaultExtrinsicParamsBuilder;
pub use subxt::dynamic::{At, Value};
use subxt::utils::{AccountId32, MultiSignature};
use subxt::{OnlineClient, PolkadotConfig};

pub use self::amount::{format_amount, one_token, parse_amount};
pub use self::facade::{Deployments, Keys, Orgs, Resources, Secrets, Staking};
pub use self::mode::Mode;
use self::mode::Refresh;
use crate::error::{Result, SdkError};

/// Default RPC endpoints; must match `testvectors/networks.json`.
const TESTNET_RPC: &str = "wss://node2.testnet.openmatter.network";
const MAINNET_RPC: &str = "wss://node2.mainnet.openmatter.network";

/// Public testnet `chain_getBlockHash(0)`, to detect which network an endpoint serves.
const TESTNET_GENESIS: &str = "d87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058";

/// Fallback mainnet signal while the mainnet genesis hash is unpinned.
const MAINNET_TOKEN_SYMBOL: &str = "MTR";

/// `MATTER_CONFIRM=yes` satisfies the mainnet confirmation guard.
const CONFIRM_ENV: &str = "MATTER_CONFIRM";
const CONFIRM_VALUE: &str = "yes";

const PROXY_PALLET: &str = "Proxy";
const PROXY_CALL: &str = "proxy";
/// Carries the wrapped call's `DispatchResult`, the only report of its failure.
const PROXY_EXECUTED_EVENT: &str = "ProxyExecuted";
/// No such delegation: the key was revoked or rebound.
const NOT_PROXY_ERROR: &str = "NotProxy";

/// `Balances.ExistentialDeposit` is `UNIT / 1000`, i.e. `10^(decimals - 3)`.
const ED_DECIMAL_OFFSET: u32 = 3;

/// Which OpenMatter network to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Network {
    /// The public testnet (default).
    Testnet,
    /// Mainnet. Signing clients need [`MatterConfig::confirm_mainnet`].
    Mainnet,
    /// Anything else (dev node, fork). Requires [`MatterConfig::rpc_url`]. The
    /// mainnet guard still applies if the endpoint serves mainnet.
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

/// How to connect. Build with [`MatterConfig::for_network`] or
/// [`MatterConfig::for_url`], then adjust fields.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MatterConfig {
    /// Which network. Default [`Network::Testnet`].
    pub network: Network,
    /// Overrides the network's default endpoint. Required for [`Network::Custom`].
    pub rpc_url: Option<String>,
    /// Acknowledges this client may spend real funds; alternatively set
    /// `MATTER_CONFIRM=yes`. Default `false`.
    pub confirm_mainnet: bool,
    /// How long to wait for a submitted extrinsic to finalize. Default 120 s.
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

/// Chain identity and unit metadata, read once at connect. The two decimal
/// counts can disagree.
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

    /// `system_properties.tokenDecimals`: **presentational**, from the node's
    /// chain-spec file, and possibly out of step with the runtime. Never use it
    /// for arithmetic.
    pub token_decimals_declared: u8,

    /// Decimals implied by the runtime's `Balances.ExistentialDeposit`
    /// (`ED == 10^(d-3)`): **consensus-backed**, and used by every SDK conversion.
    pub token_decimals_effective: u8,

    /// The raw `Balances.ExistentialDeposit`, in plancks.
    pub existential_deposit: u128,
}

impl ChainProperties {
    /// Whether the node's chain spec disagrees with the runtime it is executing.
    pub fn decimals_disagree(&self) -> bool {
        self.token_decimals_declared != self.token_decimals_effective
    }

    /// Whether this endpoint serves mainnet, and how that was detected. Only the
    /// testnet genesis hash is pinned, so the token symbol (`MTR`) stands in.
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

/// A client for MatterChain and the matter-kgc committee.
///
/// One constructor per signing intent; there is no builder, so a key and a
/// signer can never both be set.
pub struct MatterClient {
    api: OnlineClient<PolkadotConfig>,
    rpc: LegacyRpcMethods<PolkadotConfig>,
    signer: Option<Arc<dyn KeySigner>>,
    properties: ChainProperties,
    config: MatterConfig,
    /// Resolved at connect; refreshed only after a failed submission. The guard
    /// is never held across an await.
    mode: RwLock<Mode>,
}

impl MatterClient {
    /// Connect read-only. Queries work; anything that submits an extrinsic
    /// returns [`SdkError::ReadOnly`].
    pub async fn connect(config: MatterConfig) -> Result<Self> {
        Self::build(config, None).await
    }

    /// Connect with an API key, held in process under [`ApiKey`]'s guarantees.
    /// For HSM or KMS keys use [`MatterClient::connect_with_signer`]; see
    /// `docs/secure-signing.md`.
    pub async fn connect_with_api_key(config: MatterConfig, key: ApiKey) -> Result<Self> {
        Self::build(config, Some(Arc::new(key))).await
    }

    /// Connect with a signer you own (HSM, KMS, remote signer). Recommended for
    /// production.
    pub async fn connect_with_signer(
        config: MatterConfig,
        signer: Arc<dyn KeySigner>,
    ) -> Result<Self> {
        Self::build(config, Some(signer)).await
    }

    /// Connect from the environment: `MATTER_API_KEY` (else
    /// `MATTER_SIGNER_SEED`), `MATTER_RPC_URL`, `MATTER_NETWORK`
    /// (`testnet`|`mainnet`), `MATTER_CONFIRM`. With no key, connects read-only.
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

        let mut client = Self {
            api,
            rpc,
            signer,
            properties,
            config,
            mode: RwLock::new(Mode::Direct),
        };
        // Guards before any further round trip.
        client.enforce_network_guards()?;

        if let Some(account) = client.account() {
            let resolved = mode::resolve(&client.api, account).await?;
            if let Mode::Delegated { principal, scopes } = &resolved {
                // SS58, the form the dashboard shows.
                tracing::info!(
                    principal = %AccountId32(*principal.as_bytes()),
                    %scopes,
                    "acting for a member"
                );
            }
            client.mode = RwLock::new(resolved);
        }
        Ok(client)
    }

    /// Guards against spending real funds by accident. Checks what the endpoint
    /// serves, not `config.network`, so a testnet config at a mainnet URL trips.
    fn enforce_network_guards(&self) -> Result<()> {
        let (is_mainnet, detected_via) = self.properties.is_mainnet();

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

    /// Whether this client signs for itself or acts for a member. Resolved at
    /// connect.
    pub fn mode(&self) -> Mode {
        self.read_mode()
    }

    /// A poisoned lock still holds a valid `Mode`: the only writer replaces it
    /// wholesale.
    fn read_mode(&self) -> Mode {
        self.mode
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The member this client acts for, or `None` when it acts as itself.
    pub fn principal(&self) -> Option<AccountId> {
        self.read_mode().principal()
    }

    /// What this client's key is permitted to do, or `None` when the chain
    /// grants it no scoped proxy.
    pub fn scopes(&self) -> Option<ScopeSet> {
        self.read_mode().scopes()
    }

    /// The member this client acts for, as SS58. `None` when it acts as itself.
    pub fn principal_address(&self) -> Option<String> {
        self.principal()
            .map(|id| AccountId32(*id.as_bytes()).to_string())
    }

    /// The signing identity's SS58 address (prefix 42), or `None` for a
    /// read-only client.
    ///
    /// Not on [`AccountId`] to keep `matter-sdk-key` light enough for wasm.
    pub fn address(&self) -> Option<String> {
        self.account_id().map(|id| AccountId32(id).to_string())
    }

    /// The underlying subxt client, for anything this surface does not cover.
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

    /// Sign and submit `pallet.call(args)`, resolved by name against live
    /// metadata.
    ///
    /// Waits for **finalization**, not inclusion: the committee authorizes
    /// against the finalized head, so an included-only secret returns HTTP 403.
    pub async fn tx(&self, pallet: &str, call: &str, args: Vec<Value>) -> Result<TxReceipt> {
        let signer = self.require_signer()?;
        // Kept to re-check against fresh scopes on the failure path.
        let required = scopes_table::required_scopes(pallet, call, &args);
        let payload = self.build_payload(pallet, call, args)?;
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

        // Our own signer: the key may live in an HSM, and `sign` is fallible.
        let signature = signer.sign(&partial.signer_payload())?;
        let submittable =
            partial.sign_with_account_and_signature(&account, &MultiSignature::Sr25519(signature));

        let in_block = tokio::time::timeout(self.config.finality_timeout, async {
            let watching = match submittable.submit_and_watch().await {
                Ok(watching) => watching,
                Err(e) => return Err(self.submission_error(pallet, call, required, e).await),
            };
            watching
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

        let finalized = match in_block.wait_for_success().await {
            Ok(events) => events,
            Err(e) => return Err(self.outer_dispatch_error(pallet, call, e).await),
        };

        let events: Vec<(String, String)> = finalized
            .iter()
            .filter_map(|e| e.ok())
            .map(|e| (e.pallet_name().to_string(), e.variant_name().to_string()))
            .collect();

        // `proxy.proxy` succeeds even when the wrapped call fails; the failure
        // is only an event.
        if self.read_mode().is_delegated() {
            if let Some(failure) = self.inner_dispatch_error(&finalized)? {
                return Err(SdkError::Dispatch {
                    pallet: pallet.to_string(),
                    call: call.to_string(),
                    detail: failure,
                });
            }
        }

        Ok(TxReceipt {
            tx_hash,
            block_hash,
            events,
        })
    }

    /// The call to sign: as-is in [`Mode::Direct`], else wrapped in
    /// `proxy.proxy(principal, None, call)` after the local scope check.
    fn build_payload(
        &self,
        pallet: &str,
        call: &str,
        args: Vec<Value>,
    ) -> Result<subxt::tx::DynamicPayload> {
        let mode = self.read_mode();
        let Mode::Delegated { principal, scopes } = &mode else {
            return Ok(subxt::dynamic::tx(pallet, call, args));
        };

        // Never admitted inside a proxy; nesting would launder authority.
        if matches!(pallet, "Proxy" | "Utility" | "EthSigning") {
            return Err(SdkError::NeverAdmitted {
                pallet: pallet.to_string(),
                call: call.to_string(),
            });
        }

        match scopes_table::required_scopes(pallet, call, &args) {
            None => {
                return Err(SdkError::NeverAdmitted {
                    pallet: pallet.to_string(),
                    call: call.to_string(),
                })
            }
            Some(required) if !scopes.is_superset(required) => {
                return Err(SdkError::NotPermitted {
                    pallet: pallet.to_string(),
                    call: call.to_string(),
                    required,
                    held: *scopes,
                })
            }
            Some(_) => {}
        }

        Ok(proxy_payload(principal, pallet, call, args))
    }

    /// Classify a pool rejection.
    ///
    /// A revoked key surfaces here as `InvalidTransaction` (1010), not
    /// `Proxy.NotProxy`: its fee is unsponsored and it holds no funds. That code
    /// also means "nobody can pay", so re-read the grant to tell them apart.
    async fn submission_error(
        &self,
        pallet: &str,
        call: &str,
        required: Option<ScopeSet>,
        e: subxt::Error,
    ) -> SdkError {
        let mode = self.read_mode();
        let Mode::Delegated { principal, .. } = &mode else {
            return chain_error(pallet, call, e);
        };
        if !is_pool_rejection(&e) {
            return chain_error(pallet, call, e);
        }

        match self.refresh_delegation().await {
            Ok(Refresh::Gone) => SdkError::KeyRevoked,
            Ok(Refresh::Rescoped { held }) => {
                // Name the missing scope against the fresh set.
                match required {
                    Some(required) if !held.is_superset(required) => SdkError::NotPermitted {
                        pallet: pallet.to_string(),
                        call: call.to_string(),
                        required,
                        held,
                    },
                    _ => SdkError::Unsponsored {
                        principal: principal.to_string(),
                        pallet: pallet.to_string(),
                        call: call.to_string(),
                    },
                }
            }
            Ok(Refresh::Unchanged) => SdkError::Unsponsored {
                principal: principal.to_string(),
                pallet: pallet.to_string(),
                call: call.to_string(),
            },
            // The lookup failed; report the original refusal.
            Err(_) => chain_error(pallet, call, e),
        }
    }

    /// Re-read the chain's grant, updating cached scopes if they moved. A gone
    /// grant does not reset the mode to [`Mode::Direct`], so later calls keep
    /// reporting revocation rather than "cannot pay fees".
    async fn refresh_delegation(&self) -> Result<Refresh> {
        let previous = self.read_mode();
        let Some(key) = self.account() else {
            return Ok(Refresh::Unchanged);
        };
        let outcome = mode::after_refresh(&previous, mode::lookup(&self.api, key).await?);
        if let (Refresh::Rescoped { held }, Mode::Delegated { principal, .. }) =
            (outcome, &previous)
        {
            *self
                .mode
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Mode::Delegated {
                principal: *principal,
                scopes: held,
            };
        }
        Ok(outcome)
    }

    /// Classify a failure of the outer `proxy.proxy`. `Proxy.NotProxy` is
    /// reported as [`SdkError::KeyRevoked`] only once the chain confirms it.
    async fn outer_dispatch_error(&self, pallet: &str, call: &str, e: subxt::Error) -> SdkError {
        let is_not_proxy = matches!(
            &e,
            subxt::Error::Runtime(subxt::error::DispatchError::Module(m))
                if matches!(m.details(), Ok(d) if d.pallet.name() == PROXY_PALLET && d.variant.name == NOT_PROXY_ERROR)
        );
        if !is_not_proxy {
            return chain_error(pallet, call, e);
        }

        match self.refresh_delegation().await {
            Ok(Refresh::Gone) => SdkError::KeyRevoked,
            // The proxy still stands; the failure is something else.
            Ok(_) => chain_error(pallet, call, e),
            Err(lookup_failed) => lookup_failed,
        }
    }

    /// The `DispatchError` of the call a `Proxy.ProxyExecuted` event reports,
    /// rendered through metadata, or `None` if the inner call succeeded.
    fn inner_dispatch_error(
        &self,
        events: &subxt::blocks::ExtrinsicEvents<PolkadotConfig>,
    ) -> Result<Option<String>> {
        let Some(executed) = events
            .iter()
            .filter_map(|e| e.ok())
            .find(|e| e.pallet_name() == PROXY_PALLET && e.variant_name() == PROXY_EXECUTED_EVENT)
        else {
            return Ok(None);
        };

        // One `DispatchResult` field: byte 0 is the `Result` discriminant.
        let bytes = executed.field_bytes();
        match bytes.first() {
            None => Ok(Some("Proxy.ProxyExecuted carried no result".to_string())),
            Some(0) => Ok(None),
            Some(1) => {
                let decoded =
                    subxt::error::DispatchError::decode_from(&bytes[1..], self.api.metadata())
                        .map_err(|e| SdkError::Chain {
                            target: format!("{PROXY_PALLET}.{PROXY_EXECUTED_EVENT}"),
                            detail: format!("could not decode the wrapped call's error: {e}"),
                        })?;
                Ok(Some(decoded.to_string()))
            }
            Some(other) => Ok(Some(format!(
                "Proxy.ProxyExecuted carried an unknown result discriminant {other}"
            ))),
        }
    }

    /// Read a storage entry. `keys` are the map keys, empty for a plain value.
    /// `None` when absent (e.g. an unfunded account's `System.Account`).
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

    // Façade calls belong in `facade.rs`; one that needs a new `SdkError` or
    // `MatterConfig` field means the seam has leaked.

    /// Secrets: store, rotate, share, and delete secrets.
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

    /// Minting and revoking member-tied API keys. Member-signed only.
    pub fn keys(&self) -> Keys<'_> {
        Keys(self)
    }

    /// Who `key` acts for and what it may do. `None` if it holds no scoped proxy
    /// (unregistered, revoked, or runtime spec < 322).
    pub async fn agent_key(&self, key: AccountId) -> Result<Option<(AccountId, ScopeSet)>> {
        mode::lookup(&self.api, key).await
    }

    fn require_signer(&self) -> Result<&Arc<dyn KeySigner>> {
        self.signer.as_ref().ok_or(SdkError::ReadOnly)
    }
}

/// Read `MATTER_API_KEY`, falling back to `MATTER_SIGNER_SEED`.
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
        // Warn once, then trust the runtime.
        tracing::warn!(
            chain = %properties.chain_name,
            declared = properties.token_decimals_declared,
            effective = properties.token_decimals_effective,
            "chain spec and runtime disagree on token decimals; using the runtime's"
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

/// Recover `d` from `ED == 10^(d - 3)`, or `None` if `ED` is not a power of ten.
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

/// Substrate's JSON-RPC code for a transaction the pool refused to accept.
const INVALID_TRANSACTION_CODE: &str = "1010";

/// Whether the node refused the transaction at validation. Matches code `1010`
/// (the stable contract) plus the fee wording older nodes use.
fn is_pool_rejection(e: &subxt::Error) -> bool {
    let text = e.to_string();
    text.contains(INVALID_TRANSACTION_CODE)
        || text.contains("Inability to pay")
        || text.contains("InvalidTransaction")
}

/// `Proxy.proxy(MultiAddress::Id(principal), None, call)`.
///
/// The inner call is the direct path's `dynamic::tx` nested via `into_value()`.
/// `force_proxy_type` is `None`; pallet-proxy picks the matching definition.
fn proxy_payload(
    principal: &AccountId,
    pallet: &str,
    call: &str,
    args: Vec<Value>,
) -> subxt::tx::DynamicPayload {
    let inner = subxt::dynamic::tx(pallet, call, args).into_value();
    subxt::dynamic::tx(
        PROXY_PALLET,
        PROXY_CALL,
        vec![
            Value::unnamed_variant("Id", [Value::from_bytes(principal.as_bytes())]),
            Value::unnamed_variant("None", []),
            inner,
        ],
    )
}

/// Spec-330 metadata fixture; regeneration recipe in `scopes_table`'s tests.
#[cfg(test)]
pub(super) fn test_metadata() -> subxt::Metadata {
    use parity_scale_codec::Decode;
    let bytes: &[u8] = include_bytes!("../../../../testvectors/spec330_metadata.scale");
    subxt::Metadata::decode(&mut &bytes[..]).expect("fixture decodes as subxt metadata")
}

#[cfg(test)]
mod tests {
    use subxt::tx::Payload;

    use super::*;

    /// Layout: proxy pallet and call indices, `Id` variant byte, 32 account
    /// bytes, `None` variant byte, then the direct path's call bytes verbatim.
    #[test]
    fn wrapping_encodes_the_inner_call_verbatim() {
        let metadata = test_metadata();
        let principal = AccountId::from([9u8; 32]);

        let direct = subxt::dynamic::tx("Jobs", "cancel_deployment", vec![Value::u128(42)]);
        let inner_bytes = direct
            .encode_call_data(&metadata)
            .expect("the inner call encodes on its own");

        let wrapped = proxy_payload(
            &principal,
            "Jobs",
            "cancel_deployment",
            vec![Value::u128(42)],
        );
        let outer_bytes = wrapped
            .encode_call_data(&metadata)
            .expect("the wrapped call encodes");

        let proxy = metadata
            .pallet_by_name(PROXY_PALLET)
            .expect("Proxy pallet in metadata");
        let proxy_call_index = proxy
            .call_variant_by_name(PROXY_CALL)
            .expect("Proxy.proxy in metadata")
            .index;

        let mut expected = vec![proxy.index(), proxy_call_index];
        // MultiAddress::Id is variant 0, then the raw account.
        expected.push(0);
        expected.extend_from_slice(principal.as_bytes());
        // Option::None is variant 0.
        expected.push(0);
        expected.extend_from_slice(&inner_bytes);

        assert_eq!(outer_bytes, expected);
    }

    /// A `RuntimeCall` is `pallet_index ++ call_index ++ args`.
    #[test]
    fn the_nested_call_keeps_its_own_pallet_and_call_indices() {
        let metadata = test_metadata();
        let jobs = metadata.pallet_by_name("Jobs").expect("Jobs pallet");
        let cancel = jobs
            .call_variant_by_name("cancel_deployment")
            .expect("Jobs.cancel_deployment");

        let inner = subxt::dynamic::tx("Jobs", "cancel_deployment", vec![Value::u128(42)])
            .encode_call_data(&metadata)
            .unwrap();

        assert_eq!(inner[0], jobs.index());
        assert_eq!(inner[1], cancel.index);
    }

    #[test]
    fn existential_deposit_implies_the_documented_decimal_counts() {
        // UNIT = 10^18 and 10^12 runtimes.
        assert_eq!(decimals_from_existential_deposit(10u128.pow(15)), Some(18));
        assert_eq!(decimals_from_existential_deposit(10u128.pow(9)), Some(12));
        assert_eq!(decimals_from_existential_deposit(1), Some(3));
        // Not a power of ten: fall back rather than guess.
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

    /// Replays `testvectors/networks.json`, the source of truth for default endpoints.
    #[test]
    fn named_networks_have_default_endpoints() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../testvectors/networks.json")).unwrap();
        let rows = fixture["default_rpc"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let network = match row["network"].as_str().unwrap() {
                "testnet" => Network::Testnet,
                "mainnet" => Network::Mainnet,
                "custom" => Network::Custom,
                other => panic!("fixture names an unknown network `{other}`"),
            };
            assert_eq!(
                network.default_rpc_url(),
                row["url"].as_str(),
                "default endpoint for {network:?}"
            );
        }
    }

    #[test]
    fn the_default_config_is_testnet_and_unconfirmed() {
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
