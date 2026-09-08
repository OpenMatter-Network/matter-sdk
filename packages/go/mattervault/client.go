package mattervault

// The OpenMatter client: one key, every pallet.
//
// Mirrors the Rust, TypeScript, and Python MatterClient — named constructors, a
// generic metadata-driven surface, plancks-only amounts, and a mainnet guard that
// checks what the *endpoint* serves rather than what the caller configured.
//
// ChainClient remains the layer underneath and stays usable directly for anything
// this wrapper does not cover.

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

// Network names. Plain constants rather than an enum type, so the values are the
// same strings MATTER_NETWORK takes.
const (
	NetworkTestnet = "testnet"
	NetworkMainnet = "mainnet"
	NetworkCustom  = "custom"
)

// Default RPC endpoint per network.
const (
	TestnetRPC = "wss://node2.testnet.openmatter.network"
	MainnetRPC = "wss://node1.mainnet.openmatter.network"
)

// TestnetGenesis is the public testnet's genesis hash, read with
// chain_getBlockHash(0) on 2026-07-29. The only spoof-resistant network signal
// currently pinned.
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
	// means the default, which matches the store path's existing budget.
	FinalityTimeout time.Duration
	// Logger receives the two things this client says at connect: which member a
	// key acts for, and a chain whose declared decimals disagree with its
	// runtime. Nil means slog.Default(), which writes Info and above to stderr —
	// the same place and level these went before, so a caller who wants them
	// elsewhere can now say so and a caller who wants them gone can too.
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
		return "", fmt.Errorf("network %q requires an explicit RPCURL", c.Network)
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
// Both decimal counts are exposed on purpose, because they can disagree:
// TokenDecimalsDeclared comes from the node's chain-spec *file* and is
// presentational, while TokenDecimalsEffective is derived from the live runtime's
// own Balances.ExistentialDeposit and is consensus-backed. matter-node changed
// UNIT from 10^12 to 10^18 with no storage migration, so a node serving a stale
// spec reports 18 while executing a 12-decimal runtime.
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

// MatterClient is a client for the OpenMatter chain and the MatterVault committee.
//
// Three named constructors, three distinct intents. There is deliberately no
// builder: a builder would let you set both an API key and a signer and defer
// "which wins?" to run time.
type MatterClient struct {
	chain      *ChainClient
	properties ChainProperties
	signer     ExtrinsicSigner
	apiKey     *ApiKey
	config     Config
	// mu guards delegation, which a failed submission may refresh from the chain.
	// A *MatterClient is routinely shared across goroutines.
	mu sync.RWMutex
	// delegation is nil when this client's key acts as itself: a human seed, an
	// HSM key, a legacy project-tied key, or any key on a pre-322 chain.
	//
	// Read it through delegated(); a revocation never sets it back to nil, so a
	// revoked key keeps wrapping and keeps being told why, rather than quietly
	// becoming a direct signer nobody will pay for.
	delegation *Delegation
}

// delegated returns the grant this client acts under, or nil when it acts as
// itself.
func (c *MatterClient) delegated() *Delegation {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.delegation
}

// refreshDelegation re-reads the chain's grant and updates the cached scopes.
//
// Called only after a submission has already failed: the answer decides whether
// the cause was a revocation, a re-scope, or something nobody can pay for.
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

// classifySubmissionFailure explains a failed submission by asking the chain
// what the key may now do.
//
// A pool rejection has two indistinguishable causes — the delegation is gone, or
// nobody can pay — and the message says neither. So rather than guess from text,
// re-read the grant and let the answer decide.
func (c *MatterClient) classifySubmissionFailure(target string, call types.Call, err error) error {
	if c.delegated() == nil || !isPoolRejection(err) {
		return err
	}
	outcome, refreshErr := c.refreshDelegation()
	if refreshErr != nil {
		// The lookup failed too, so nothing new is known: report the refusal
		// itself rather than a diagnostic error about it.
		return err
	}
	switch outcome {
	case refreshGone:
		return wrapChainError(KindKeyRevoked, target, err,
			"this key's proxy is gone or now points at a different member, so %s was "+
				"refused; mint a new key or have the member re-authorize this one", target)
	case refreshRescoped:
		// The scopes moved under us: if the call is now out of scope, say so with
		// the fresh set rather than blaming the payer.
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

// ConnectWithApiKey connects with an OpenMatter API key.
//
// The key is held in process under the guarantees documented on ApiKey. For
// production keys in an HSM or KMS, prefer ConnectWithSigner — see
// docs/secure-signing.md. The client does not take ownership of the key: close it
// yourself when done.
func ConnectWithApiKey(config Config, key *ApiKey) (*MatterClient, error) {
	if key == nil {
		return nil, fmt.Errorf("api key is nil; use Connect for a read-only client")
	}
	return build(config, key, key)
}

// ConnectWithSigner connects with a signer you own — an HSM, a KMS, a remote
// signing service. The recommended production path.
func ConnectWithSigner(config Config, signer ExtrinsicSigner) (*MatterClient, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is nil; use Connect for a read-only client")
	}
	return build(config, nil, signer)
}

// ConnectFromEnv connects from MATTER_API_KEY (falling back to MATTER_SIGNER_SEED),
// MATTER_RPC_URL, MATTER_NETWORK, and MATTER_CONFIRM.
//
// With no key set this connects read-only rather than failing, so the same code
// path serves read-only tooling. The caller owns the returned key and should Close
// it; it is nil for a read-only client.
func ConnectFromEnv() (*MatterClient, *ApiKey, error) {
	network := os.Getenv("MATTER_NETWORK")
	if network != "" && network != NetworkTestnet && network != NetworkMainnet {
		return nil, nil, fmt.Errorf(
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
	// Guards first: refusing to touch mainnet unconfirmed should not cost a
	// round trip, and a wrong-network client has nothing to resolve.
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
		// Not a clean power of ten: the runtime changed its ED policy. Fall back
		// rather than reporting a confidently wrong exponent.
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
		// Loud once, then trust the runtime. Quiet success, loud surprise.
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

// decimalsFromExistentialDeposit recovers the decimal count from ED == 10^(d-3).
//
// Reports false when the constant is not a clean power of ten, meaning the runtime
// changed its ED policy — better to fall back than to report a confidently wrong
// exponent.
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

// enforceNetworkGuards applies two guards, both about not spending real money by
// accident.
//
// The checks are on what the *endpoint* actually serves, not on the configured
// network — pointing a testnet config at a mainnet URL must still trip, which is
// exactly the hole a config-flag check would leave open.
func (c *MatterClient) enforceNetworkGuards() error {
	isMainnet, detectedVia := c.properties.IsMainnet()

	// A typo'd URL should fail before it costs anything.
	if c.config.network() == NetworkTestnet && isMainnet {
		return fmt.Errorf(
			"expected the testnet network but the endpoint serves %q", c.properties.ChainName)
	}

	// Read-only mainnet access needs no confirmation.
	if !isMainnet || c.signer == nil {
		return nil
	}
	if c.config.ConfirmMainnet || os.Getenv(confirmEnv) == confirmValue {
		return nil
	}
	return fmt.Errorf(
		"refusing to build a signing client against mainnet %q (detected via %s) without "+
			"explicit confirmation: set %s=%s or Config.ConfirmMainnet. This client can "+
			"spend real funds",
		c.properties.ChainName, detectedVia, confirmEnv, confirmValue)
}

// Properties returns the chain identity and unit metadata read at connect.
func (c *MatterClient) Properties() ChainProperties { return c.properties }

// Chain returns the underlying chain client, for anything this surface does not
// cover. Exposed deliberately: a client that cannot be escaped from is a client
// that blocks work.
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

// Address returns the signing identity's SS58 address, or "" if read-only.
//
// Uses the prefix the chain actually reports rather than a constant, so a chain with
// a registered prefix renders correctly. Every binding exposes this, so the same key
// prints the same address in all four.
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
		return nil, fmt.Errorf("this client is read-only: connect with an api key or a signer")
	}
	return SubstrateSigner(c.signer.AccountID(), c.signer.SignExtrinsic)
}

// --- amounts ---------------------------------------------------------------

// ParseAmount converts a decimal token amount to plancks, at this chain's effective
// decimals. Rejects more fractional digits than the chain supports rather than
// truncating — silent truncation is how people lose money.
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

// --- the generic surface ---------------------------------------------------

// Tx signs and submits pallet.call(params), returning the transaction hash.
//
// Resolution is by name against live metadata, so this reaches every pallet the
// runtime exposes. Use ChainClient.WaitForFinalized with a domain check to confirm
// the effect — the committee authorizes against the finalized head.
//
// Under a member-tied API key the call is wrapped in proxy.proxy and runs as the
// key's principal, and any scope it lacks is refused here rather than submitted.
// On that path "submitted" carries even less information than usual, because
// proxy.proxy succeeds as an extrinsic even when the call it wrapped failed —
// prefer TxAndWait, which decodes that outcome instead of leaving it to the
// caller.
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

// TxAndWait is Tx followed to finalization, with the outcome decoded.
//
// Prefer it under a member-tied key. `proxy.proxy` succeeds as an extrinsic even
// when the call it wrapped was refused, so a wrapped failure is reported here as
// a ChainError of KindDispatch and never as a receipt — the one place that
// distinction is available at all.
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
	// The inner call nests as an argument unchanged: types.Call has no custom
	// Encode, so the generic encoder emits pallet ++ call ++ args, which is
	// exactly a RuntimeCall on the wire. Correct, but correct by accident — the
	// byte layout is pinned in scopes_test.go rather than trusted.
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

// PrincipalAddress is the member this client acts for, as SS58 — the form the
// dashboard showed whoever minted the key. Empty when it acts as itself.
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

// refuseIfOutOfScope rejects, before submitting, a call this client's key cannot
// make.
//
// A courtesy, not a boundary: the runtime is the enforcer. It exists because a
// delegated key holds no balance, so the chain's answer to "your key may not do
// that" is a complaint about *fees* that names neither the call nor the scope.
//
// Go submits an already-encoded call, so the names come back out of metadata.
// A call whose names cannot be resolved is refused rather than waved through —
// an unresolvable call index is not something to submit hopefully.
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

// checkScopes is the decision refuseIfOutOfScope makes, split out so it can be
// tested without a chain or metadata.
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

// Query reads a storage entry into result. Reports false when the entry is absent,
// which is normal control flow.
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

// Close releases the connection. It does not close an ApiKey the caller supplied —
// the caller owns that.
func (c *MatterClient) Close() { c.chain.Close() }

// classifyDispatchFailure refines a wrapped-call failure that names a revoked
// proxy.
//
// Proxy.NotProxy on the outer extrinsic means pallet-proxy found no definition
// for this (key, member) pair, which in practice means the key was revoked or
// rebound since connect. Confirm that against the chain before saying so.
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

// ss58OrHex renders an account the way a person can compare it against what the
// dashboard shows them.
func ss58OrHex(account []byte, prefix uint16) string {
	return subkey.SS58Encode(account, prefix)
}
