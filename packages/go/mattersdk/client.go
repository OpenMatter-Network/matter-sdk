package mattersdk

import (
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	subkey "github.com/vedhavyas/go-subkey/v2"
)

// Network names: the values MATTER_NETWORK takes.
const (
	NetworkTestnet = "testnet"
	NetworkMainnet = "mainnet"
	NetworkCustom  = "custom"
)

// Default RPC endpoint per network. Pinned for every binding by testvectors/networks.json.
const (
	TestnetRPC = "wss://node2.testnet.openmatter.network"
	MainnetRPC = "wss://node2.mainnet.openmatter.network"
)

// TestnetGenesis is the public testnet's genesis hash: the only pinned
// spoof-resistant network signal.
const TestnetGenesis = "0xd87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058"

// MainnetTokenSymbol is the fallback network signal while the mainnet genesis hash
// is unpinned: mainnet mints MTR, testnet MTR-Test.
const MainnetTokenSymbol = "MTR"

const (
	confirmEnv   = "MATTER_CONFIRM"
	confirmValue = "yes"

	// Balances.ExistentialDeposit is UNIT / 1000, i.e. 10^(decimals - 3).
	edDecimalOffset = 3

	// ss58 prefix to assume when the node does not report one.
	defaultSS58Prefix = 42
)

// Config is how to connect.
type Config struct {
	// Network selects a default endpoint. Empty means testnet.
	Network string
	// RPCURL overrides the network's default endpoint. Required for NetworkCustom.
	RPCURL string
	// ConfirmMainnet is an in-code acknowledgement that this client may spend real
	// funds. Also satisfiable with MATTER_CONFIRM=yes.
	ConfirmMainnet bool
	// FinalityTimeout bounds how long TxAndWait waits for finalization. Zero
	// means two minutes.
	FinalityTimeout time.Duration
	// Logger receives connect-time notices: which member a key acts for, and a
	// decimals disagreement. Nil means slog.Default().
	Logger *slog.Logger
}

// logger is the configured logger, or the process default.
func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c Config) resolveURL() (string, error) {
	if c.RPCURL != "" {
		return c.RPCURL, nil
	}
	switch c.Network {
	case "", NetworkTestnet:
		return TestnetRPC, nil
	case NetworkMainnet:
		return MainnetRPC, nil
	default:
		return "", chainErrorf(KindConfig, "", "network %q requires an explicit RPCURL", c.Network)
	}
}

func (c Config) network() string {
	if c.Network == "" {
		return NetworkTestnet
	}
	return c.Network
}

// ChainProperties is chain identity and unit metadata, read once at connect.
//
// TokenDecimalsDeclared comes from the node's chain spec and is presentational.
// TokenDecimalsEffective is derived from the runtime's Balances.ExistentialDeposit
// and is consensus-backed; amounts use it. The two can disagree on a stale spec.
type ChainProperties struct {
	GenesisHash            string
	ChainName              string
	SpecVersion            uint32
	TokenSymbol            string
	SS58Prefix             uint16
	TokenDecimalsDeclared  uint8
	TokenDecimalsEffective uint8
	ExistentialDeposit     *big.Int
}

// DecimalsDisagree reports whether the node's chain spec disagrees with the runtime
// it is executing.
func (p ChainProperties) DecimalsDisagree() bool {
	return p.TokenDecimalsDeclared != p.TokenDecimalsEffective
}

// IsMainnet reports whether this endpoint serves mainnet, and how that was decided.
// Genesis hash wins where it is pinned.
func (p ChainProperties) IsMainnet() (bool, string) {
	if p.GenesisHash == TestnetGenesis {
		return false, "genesis-hash"
	}
	return p.TokenSymbol == MainnetTokenSymbol, "token-symbol"
}

// MatterClient is a client for the OpenMatter chain and the matter-kgc committee.
// Build it with Connect, ConnectWithApiKey, or ConnectWithSigner; there is no
// builder, so a key and a signer can never both be set.
type MatterClient struct {
	chain      *ChainClient
	properties ChainProperties
	signer     ExtrinsicSigner
	apiKey     *ApiKey
	config     Config
	// mu guards delegation, which a failed submission may refresh.
	mu sync.RWMutex
	// delegation is nil when the key acts as itself: a human seed, an HSM key, a
	// project-tied key, or any key on a runtime before spec 322. Read it through
	// delegated(). A revocation never resets it to nil; see afterRefresh.
	delegation *Delegation
}

// delegated returns the grant this client acts under, or nil when it acts as
// itself.
func (c *MatterClient) delegated() *Delegation {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.delegation
}

// refreshDelegation re-reads the chain's grant after a failed submission, to tell
// a revocation from a re-scope from an unsponsored call.
func (c *MatterClient) refreshDelegation() (refreshOutcome, error) {
	previous := c.delegated()
	if previous == nil || c.signer == nil {
		return refreshUnchanged, nil
	}
	fresh, err := c.chain.AgentKey(c.signer.AccountID())
	if err != nil {
		return refreshUnchanged, err
	}
	outcome := afterRefresh(previous, fresh)
	if outcome == refreshRescoped {
		c.mu.Lock()
		c.delegation = fresh
		c.mu.Unlock()
	}
	return outcome, nil
}

// classifySubmissionFailure explains a pool rejection by re-reading the grant:
// the rejection text cannot tell a revoked delegation from an unpaid fee.
func (c *MatterClient) classifySubmissionFailure(target string, call types.Call, err error) error {
	if c.delegated() == nil || !isPoolRejection(err) {
		return err
	}
	outcome, refreshErr := c.refreshDelegation()
	if refreshErr != nil {
		// Nothing new is known; report the original refusal.
		return err
	}
	switch outcome {
	case refreshGone:
		return wrapChainError(KindKeyRevoked, target, err,
			"this key's proxy is gone or now points at a different member, so %s was "+
				"refused; mint a new key or have the member re-authorize this one", target)
	case refreshRescoped:
		// Report an out-of-scope call against the fresh scopes, not the payer.
		if scopeErr := c.refuseIfOutOfScope(call); scopeErr != nil {
			return scopeErr
		}
	}
	principal := "your principal"
	if held := c.delegated(); held != nil {
		principal = ss58OrHex(held.Principal, c.properties.SS58Prefix)
	}
	return wrapChainError(KindUnsponsored, target, err,
		"%s is within this key's scopes, but nobody would pay for it: %s and their "+
			"billing org must cover the fee", target, principal)
}

// Connect connects read-only. Queries work; submitting returns an error.
func Connect(config Config) (*MatterClient, error) {
	return build(config, nil, nil)
}

// ConnectWithApiKey connects with an in-process OpenMatter API key. For HSM or
// KMS keys prefer ConnectWithSigner (docs/secure-signing.md). The client does not
// own the key: Close it yourself.
func ConnectWithApiKey(config Config, key *ApiKey) (*MatterClient, error) {
	if key == nil {
		return nil, chainErrorf(KindConfig, "", "api key is nil; use Connect for a read-only client")
	}
	return build(config, key, key)
}

// ConnectWithSigner connects with a signer you own (HSM, KMS, remote signing
// service). The recommended production path.
func ConnectWithSigner(config Config, signer ExtrinsicSigner) (*MatterClient, error) {
	if signer == nil {
		return nil, chainErrorf(KindConfig, "", "signer is nil; use Connect for a read-only client")
	}
	return build(config, nil, signer)
}

// ConnectFromEnv connects from MATTER_API_KEY (falling back to MATTER_SIGNER_SEED),
// MATTER_RPC_URL, MATTER_NETWORK, and MATTER_CONFIRM.
//
// With no key set it connects read-only. The caller owns the returned key (nil
// when read-only) and should Close it.
func ConnectFromEnv() (*MatterClient, *ApiKey, error) {
	network := os.Getenv("MATTER_NETWORK")
	if network != "" && network != NetworkTestnet && network != NetworkMainnet {
		return nil, nil, chainErrorf(KindConfig, "",
			"MATTER_NETWORK must be %q or %q, got %q", NetworkTestnet, NetworkMainnet, network)
	}
	config := Config{Network: network, RPCURL: os.Getenv("MATTER_RPC_URL")}

	for _, name := range []string{"MATTER_API_KEY", "MATTER_SIGNER_SEED"} {
		value := os.Getenv(name)
		if strings.TrimSpace(value) == "" {
			continue
		}
		key, err := NewApiKey(value)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing the key from %s: %w", name, err)
		}
		client, err := ConnectWithApiKey(config, key)
		if err != nil {
			key.Close()
			return nil, nil, err
		}
		return client, key, nil
	}

	client, err := Connect(config)
	return client, nil, err
}

func build(config Config, key *ApiKey, signer ExtrinsicSigner) (*MatterClient, error) {
	url, err := config.resolveURL()
	if err != nil {
		return nil, err
	}
	chain, err := NewChainClient(url)
	if err != nil {
		return nil, err
	}
	log := config.logger()
	properties, err := readProperties(chain, log)
	if err != nil {
		return nil, err
	}

	client := &MatterClient{
		chain:      chain,
		properties: properties,
		signer:     signer,
		apiKey:     key,
		config:     config,
	}
	// Guards first: they need no further round trip.
	if err := client.enforceNetworkGuards(); err != nil {
		return nil, err
	}
	if signer != nil {
		delegation, err := resolveDelegation(chain, signer.AccountID(), properties.SS58Prefix, log)
		if err != nil {
			return nil, err
		}
		client.delegation = delegation
	}
	return client, nil
}

func readProperties(chain *ChainClient, log *slog.Logger) (ChainProperties, error) {
	var props ChainProperties

	var systemProperties struct {
		TokenSymbol   string `json:"tokenSymbol"`
		TokenDecimals uint8  `json:"tokenDecimals"`
		SS58Format    uint16 `json:"ss58Format"`
	}
	if err := chain.api.Client.Call(&systemProperties, "system_properties"); err != nil {
		return props, fmt.Errorf("system_properties: %w", err)
	}
	var chainName string
	if err := chain.api.Client.Call(&chainName, "system_chain"); err != nil {
		return props, fmt.Errorf("system_chain: %w", err)
	}
	genesis, err := chain.api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		return props, fmt.Errorf("genesis hash: %w", err)
	}
	runtime, err := chain.api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return props, fmt.Errorf("runtime version: %w", err)
	}

	// The consensus-backed decimal count: ED == 10^(d-3).
	raw, err := chain.Constant("Balances", "ExistentialDeposit")
	if err != nil {
		return props, err
	}
	ed := decodeU128LE(raw)
	effective, ok := decimalsFromExistentialDeposit(ed)
	if !ok {
		// Not a clean power of ten: fall back to the declared count.
		effective = systemProperties.TokenDecimals
	}

	ss58 := systemProperties.SS58Format
	if ss58 == 0 {
		ss58 = defaultSS58Prefix
	}

	props = ChainProperties{
		GenesisHash:            genesis.Hex(),
		ChainName:              chainName,
		SpecVersion:            uint32(runtime.SpecVersion),
		TokenSymbol:            systemProperties.TokenSymbol,
		SS58Prefix:             ss58,
		TokenDecimalsDeclared:  systemProperties.TokenDecimals,
		TokenDecimalsEffective: effective,
		ExistentialDeposit:     ed,
	}

	if props.DecimalsDisagree() {
		// Warn once, then trust the runtime.
		log.Warn(
			"chain spec and runtime disagree on token decimals; using the runtime's",
			"chain", props.ChainName,
			"declared", props.TokenDecimalsDeclared,
			"effective", props.TokenDecimalsEffective)
	}
	return props, nil
}

// decodeU128LE reads a little-endian u128 from raw SCALE bytes.
func decodeU128LE(raw []byte) *big.Int {
	if len(raw) < 16 {
		return big.NewInt(0)
	}
	be := make([]byte, 16)
	for i := 0; i < 16; i++ {
		be[15-i] = raw[i]
	}
	return new(big.Int).SetBytes(be)
}

// decimalsFromExistentialDeposit recovers d from ED == 10^(d-3). Reports false
// when ED is not a clean power of ten.
func decimalsFromExistentialDeposit(ed *big.Int) (uint8, bool) {
	if ed == nil || ed.Sign() <= 0 {
		return 0, false
	}
	value := new(big.Int).Set(ed)
	ten := big.NewInt(10)
	one := big.NewInt(1)
	mod := new(big.Int)
	exponent := 0
	for value.Cmp(one) > 0 {
		if mod.Mod(value, ten).Sign() != 0 {
			return 0, false
		}
		value.Div(value, ten)
		exponent++
	}
	return uint8(exponent + edDecimalOffset), true
}

// enforceNetworkGuards refuses a testnet config whose endpoint serves mainnet, and
// an unconfirmed signing client on mainnet. Both check what the endpoint serves,
// not the configured network.
func (c *MatterClient) enforceNetworkGuards() error {
	isMainnet, detectedVia := c.properties.IsMainnet()

	// A typo'd URL should fail before it costs anything.
	if c.config.network() == NetworkTestnet && isMainnet {
		return chainErrorf(KindWrongNetwork, "",
			"expected the testnet network but the endpoint serves %q", c.properties.ChainName)
	}

	// Read-only mainnet access needs no confirmation.
	if !isMainnet || c.signer == nil {
		return nil
	}
	if c.config.ConfirmMainnet || os.Getenv(confirmEnv) == confirmValue {
		return nil
	}
	return chainErrorf(KindMainnetNotConfirmed, "",
		"refusing to build a signing client against mainnet %q (detected via %s) without "+
			"explicit confirmation: set %s=%s or Config.ConfirmMainnet. This client can "+
			"spend real funds",
		c.properties.ChainName, detectedVia, confirmEnv, confirmValue)
}

// Properties returns the chain identity and unit metadata read at connect.
func (c *MatterClient) Properties() ChainProperties { return c.properties }

// Chain returns the underlying chain client, for anything this surface does not
// cover.
func (c *MatterClient) Chain() *ChainClient { return c.chain }

// AccountID returns the signing identity's 32-byte account id, or nil if read-only.
func (c *MatterClient) AccountID() []byte {
	if c.signer == nil {
		return nil
	}
	return c.signer.AccountID()
}

// AccountIDHex returns the account id as 0x + 64 hex characters, or "" if read-only.
func (c *MatterClient) AccountIDHex() string {
	if id := c.AccountID(); id != nil {
		return toHex(id)
	}
	return ""
}

// Address returns the signing identity's SS58 address under the chain's reported
// prefix, or "" if read-only.
func (c *MatterClient) Address() string {
	id := c.AccountID()
	if id == nil {
		return ""
	}
	return subkey.SS58Encode(id, c.properties.SS58Prefix)
}

// Signer returns a committee Signer for this identity, so one key both submits
// extrinsics and authorizes /partial-decrypt requests.
func (c *MatterClient) Signer() (Signer, error) {
	if c.apiKey != nil {
		return c.apiKey.Signer()
	}
	if c.signer == nil {
		return nil, chainErrorf(KindReadOnly, "", "this client is read-only: connect with an api key or a signer")
	}
	return SubstrateSigner(c.signer.AccountID(), c.signer.SignExtrinsic)
}

// ParseAmount converts a decimal token amount to plancks at this chain's effective
// decimals, rejecting excess fractional digits rather than truncating.
func (c *MatterClient) ParseAmount(text string) (*big.Int, error) {
	return ParseAmount(text, c.properties.TokenDecimalsEffective)
}

// FormatAmount renders plancks as a decimal string, at this chain's effective
// decimals.
func (c *MatterClient) FormatAmount(plancks *big.Int) string {
	return FormatAmount(plancks, c.properties.TokenDecimalsEffective)
}

// OneToken returns one whole token in plancks, on this chain.
func (c *MatterClient) OneToken() *big.Int {
	return OneToken(c.properties.TokenDecimalsEffective)
}

// Tx signs and submits a prebuilt call and returns the transaction hash without
// waiting for finalization. Most callers want Call or TxAndWait.
//
// Under a member-tied API key the call is wrapped in proxy.proxy and runs as the
// key's principal; a call outside the key's scopes is refused before submission.
// proxy.proxy succeeds even when the wrapped call fails, and only TxAndWait
// reports that.
func (c *MatterClient) Tx(call types.Call) (string, error) {
	outgoing, err := c.prepare(call)
	if err != nil {
		return "", err
	}
	hash, err := c.chain.SubmitCall(c.signer, outgoing)
	if err != nil {
		return "", c.classifySubmissionFailure(c.callTarget(call), call, err)
	}
	return hash, nil
}

// TxAndWait is Tx followed to finalization, with the outcome decoded. A refused
// wrapped call is returned as a ChainError of KindDispatch, never as a receipt.
func (c *MatterClient) TxAndWait(call types.Call) (TxReceipt, error) {
	outgoing, err := c.prepare(call)
	if err != nil {
		return TxReceipt{}, err
	}
	target := c.callTarget(call)
	receipt, outcome, err := c.chain.SubmitAndWatch(c.signer, outgoing, c.config.FinalityTimeout)
	if err != nil {
		return TxReceipt{}, c.classifySubmissionFailure(target, call, err)
	}
	if err := delegatedOutcome(outcome, c.delegated() != nil, target, c.chain.describeDispatchError); err != nil {
		return TxReceipt{}, c.classifyDispatchFailure(target, outcome, err)
	}
	return receipt, nil
}

// prepare applies the read-only guard and the scope check, and wraps the call in
// proxy.proxy when this client acts for a member.
func (c *MatterClient) prepare(call types.Call) (types.Call, error) {
	if c.signer == nil {
		return types.Call{}, chainErrorf(KindReadOnly, "",
			"this client is read-only: connect with an api key or a signer to submit")
	}
	delegation := c.delegated()
	if delegation == nil {
		return call, nil
	}

	if err := c.refuseIfOutOfScope(call); err != nil {
		return types.Call{}, err
	}
	principal, err := types.NewMultiAddressFromAccountID(delegation.Principal)
	if err != nil {
		return types.Call{}, fmt.Errorf("encoding the principal: %w", err)
	}
	// types.Call has no custom Encode, so it nests as pallet ++ call ++ args: a
	// RuntimeCall on the wire. scopes_test.go pins this layout.
	wrapped, err := types.NewCall(
		c.chain.meta, proxyCall, principal, forceProxyTypeNone{}, call,
	)
	if err != nil {
		return types.Call{}, fmt.Errorf("wrapping the call for %s: %w", proxyCall, err)
	}
	return wrapped, nil
}

// callTarget names a call for an error message, falling back to its index when
// metadata cannot name it.
func (c *MatterClient) callTarget(call types.Call) string {
	if pallet, method, ok := callNames(c.chain.meta, call.CallIndex); ok {
		return pallet + "." + method
	}
	return fmt.Sprintf("call %d.%d", call.CallIndex.SectionIndex, call.CallIndex.MethodIndex)
}

// IsDelegated reports whether this client's key acts for a member rather than
// for itself.
func (c *MatterClient) IsDelegated() bool { return c.delegated() != nil }

// Principal is the member this client acts for, or nil when it acts as itself.
func (c *MatterClient) Principal() []byte {
	delegation := c.delegated()
	if delegation == nil {
		return nil
	}
	return delegation.Principal
}

// PrincipalAddress is the member this client acts for, as SS58, or "" when it
// acts as itself.
func (c *MatterClient) PrincipalAddress() string {
	principal := c.Principal()
	if principal == nil {
		return ""
	}
	return ss58OrHex(principal, c.properties.SS58Prefix)
}

// Scopes is what this client's key may do, and whether the chain grants it a
// scoped proxy at all.
func (c *MatterClient) Scopes() (ScopeSet, bool) {
	delegation := c.delegated()
	if delegation == nil {
		return ScopeSet{}, false
	}
	return delegation.Scopes, true
}

// AgentKey reports who `key` acts for and what it may do, per the chain, or nil
// if it holds no scoped proxy. A read, so it needs no signer.
func (c *MatterClient) AgentKey(key []byte) (*Delegation, error) {
	return c.chain.AgentKey(key)
}

// refuseIfOutOfScope rejects, before submission, a call this key cannot make.
// A courtesy, not a boundary: the runtime enforces scopes, but reports a refusal
// only as a fee error. A call index metadata cannot name is refused.
func (c *MatterClient) refuseIfOutOfScope(call types.Call) error {
	pallet, method, ok := callNames(c.chain.meta, call.CallIndex)
	if !ok {
		return chainErrorf(KindChain, "",
			"cannot resolve call index %d.%d in the live metadata, so its required "+
				"scopes are unknown; refusing to submit it as a delegated key",
			call.CallIndex.SectionIndex, call.CallIndex.MethodIndex)
	}
	target := pallet + "." + method

	// The runtime never admits these inside a proxy, and nesting one would let a
	// key launder authority through a batch.
	if pallet == "Proxy" || pallet == "Utility" || pallet == "EthSigning" {
		return chainErrorf(KindNeverAdmitted, target,
			"%s is never admitted to an api key; sign it with the member's own key",
			target)
	}
	required, admitted := requiredScopesForCall(c.chain.meta, c.chain.calls, call)
	if !admitted {
		return chainErrorf(KindNeverAdmitted, target,
			"%s is never admitted to an api key; sign it with the member's own key",
			target)
	}
	held := c.delegated().Scopes
	if !held.IsSuperset(required) {
		return chainErrorf(KindNotPermitted, target,
			"key lacks %s for %s; it holds %s", required, target, held)
	}
	return nil
}

// checkScopes is refuseIfOutOfScope's decision, testable without a chain.
func checkScopes(pallet, method string, held ScopeSet) error {
	target := pallet + "." + method

	// The runtime never admits these inside a proxy, and nesting one would let a
	// key launder authority through a batch.
	if pallet == "Proxy" || pallet == "Utility" || pallet == "EthSigning" {
		return chainErrorf(KindNeverAdmitted, target,
			"%s is never admitted to an api key; sign it with the member's own key",
			target)
	}

	required, admitted := RequiredScopes(pallet, method)
	if !admitted {
		return chainErrorf(KindNeverAdmitted, target,
			"%s is never admitted to an api key; sign it with the member's own key",
			target)
	}
	if !held.IsSuperset(required) {
		return chainErrorf(KindNotPermitted, target,
			"key lacks %s for %s; it holds %s", required, target, held)
	}
	return nil
}

// Query reads a storage entry into result. Reports false when the entry is absent.
func (c *MatterClient) Query(result any, pallet, entry string, keys ...[]byte) (bool, error) {
	return c.chain.Query(result, pallet, entry, keys...)
}

// QueryRaw reads a storage entry as undecoded SCALE bytes. Nil means absent.
func (c *MatterClient) QueryRaw(pallet, entry string, keys ...[]byte) ([]byte, error) {
	return c.chain.QueryRaw(pallet, entry, keys...)
}

// RuntimeAPI calls a runtime API by its state_call name.
func (c *MatterClient) RuntimeAPI(method string, args []byte) ([]byte, error) {
	return c.chain.RuntimeAPI(method, args)
}

// Constant reads a pallet constant from the live metadata.
func (c *MatterClient) Constant(pallet, name string) ([]byte, error) {
	return c.chain.Constant(pallet, name)
}

// Close releases the connection. It does not close a caller-supplied ApiKey.
func (c *MatterClient) Close() { c.chain.Close() }

// classifyDispatchFailure reports Proxy.NotProxy (no proxy for this key/member
// pair) as KindKeyRevoked once the chain confirms the grant is gone.
func (c *MatterClient) classifyDispatchFailure(target string, outcome extrinsicOutcome, err error) error {
	if c.delegated() == nil || outcome.Failed == nil || !outcome.Failed.IsModule {
		return err
	}
	if meta, findErr := c.chain.meta.FindError(
		outcome.Failed.ModuleError.Index, outcome.Failed.ModuleError.Error,
	); findErr != nil || meta == nil || string(meta.Name) != proxyPallet || string(meta.Value) != notProxyError {
		return err
	}
	if refreshed, refreshErr := c.refreshDelegation(); refreshErr == nil && refreshed == refreshGone {
		return wrapChainError(KindKeyRevoked, target, err,
			"this key's proxy is gone or now points at a different member, so %s was "+
				"refused; mint a new key or have the member re-authorize this one", target)
	}
	return err
}

// ss58OrHex renders an account as the dashboard shows it.
func ss58OrHex(account []byte, prefix uint16) string {
	return subkey.SS58Encode(account, prefix)
}
