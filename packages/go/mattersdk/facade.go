package mattersdk

// Typed façades for common domains. A write is a thin named wrapper over
// MatterClient.Call. A read takes one block's state, fetches its sources there,
// and hands the raw bytes to a pure decoder in read_*.go. Anything not here is one
// client.Call, client.Tx or client.Query away.
//
// Names resolve at call time from live metadata. testvectors/facade_calls.json
// (writes), testvectors/facade_reads.json (reads) and facade_test.go pin the
// surface both ways: a fixture row without a method fails, and a method without a
// row fails.
//
// Every write waits for finalization and returns a TxReceipt. Under a member-tied
// key, a call refused inside proxy.proxy is a ChainError of KindDispatch, never a
// receipt.

import (
	"fmt"
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

// Call signs and submits pallet.method(args...), resolved by name against live
// metadata, and waits for finalization. Arguments are go-substrate-rpc-client
// values (types.NewU32, types.NewBytes, ...) in the call's declared order.
func (c *MatterClient) Call(pallet, method string, args ...any) (TxReceipt, error) {
	built, err := types.NewCall(c.chain.meta, pallet+"."+method, args...)
	if err != nil {
		return TxReceipt{}, wrapChainError(KindChain, pallet+"."+method, err, "cannot build %s.%s: %v", pallet, method, err)
	}
	return c.TxAndWait(built)
}

// call is Call for the façades. Tests set submitCall to capture the built call.
func (c *MatterClient) call(pallet, method string, args ...any) (TxReceipt, error) {
	if c.submitCall == nil {
		return c.Call(pallet, method, args...)
	}
	built, err := types.NewCall(c.chain.meta, pallet+"."+method, args...)
	if err != nil {
		return TxReceipt{}, err
	}
	return c.submitCall(built)
}

// AccountsFacade reads what an account holds and how much of it can move. Reads
// only, at the latest finalized block unless pinned with At; it works on a
// read-only client.
type AccountsFacade struct {
	client *MatterClient
	pin    *[blockHashBytes]byte
}

// Accounts returns the accounts façade.
func (c *MatterClient) Accounts() AccountsFacade { return AccountsFacade{client: c} }

// At reads at block (a block hash) instead of the latest finalized block, so
// several reads share one view of the chain.
func (f AccountsFacade) At(block [32]byte) AccountsFacade {
	return AccountsFacade{client: f.client, pin: &block}
}

// Balance reports what who holds: free, on hold and frozen amounts, what a
// transfer may move, and the reasons behind each hold and freeze. who is a
// 32-byte account id (see ParseAccount for text). An account the chain does not
// store reads as zeros with Exists false.
func (f AccountsFacade) Balance(who []byte) (AccountBalance, error) {
	if len(who) != accountIDBytes {
		return AccountBalance{}, ErrBadAccount
	}
	view, err := f.client.snapshot(f.pin)
	if err != nil {
		return AccountBalance{}, err
	}
	values, err := view.storage(balanceRequests(who))
	if err != nil {
		return AccountBalance{}, err
	}
	properties := f.client.properties
	return decodeBalance(newAddress(who, properties.SS58Prefix), properties.ExistentialDeposit, values)
}

// FeesFacade reads what a call would cost, and who would be charged for it.
// Reads only, at the latest finalized block unless pinned with At.
type FeesFacade struct {
	client *MatterClient
	pin    *[blockHashBytes]byte
}

// Fees returns the fees façade.
func (c *MatterClient) Fees() FeesFacade { return FeesFacade{client: c} }

// At reads at block (a block hash) instead of the latest finalized block, so
// several reads share one view of the chain.
func (f FeesFacade) At(block [32]byte) FeesFacade {
	return FeesFacade{client: f.client, pin: &block}
}

// Estimate reports what pallet.method(args...) would cost this client, and who
// would be charged. It takes exactly what Call takes, and prices the call as it
// would be submitted: wrapped in proxy.proxy when the client acts for a member.
// Nothing is signed or submitted.
//
// An estimate, not a quote: the fee is computed for an upper bound on the signed
// length, with no tip. It is also not a permission check; a call a scoped key may
// not make is still priced. It works on a read-only client, which learns the fee
// but not the payer.
func (f FeesFacade) Estimate(pallet, method string, args ...any) (FeeEstimate, error) {
	client := f.client
	target := pallet + "." + method
	built, err := types.NewCall(client.chain.meta, target, args...)
	if err != nil {
		return FeeEstimate{}, wrapChainError(KindChain, target, err, "cannot build %s: %v", target, err)
	}
	delegation := client.delegated()
	if delegation != nil {
		if built, err = client.wrapFor(delegation, built); err != nil {
			return FeeEstimate{}, wrapChainError(KindChain, target, err, "cannot build %s: %v", target, err)
		}
	}
	callBytes, err := codec.Encode(built)
	if err != nil {
		return FeeEstimate{}, wrapChainError(KindChain, target, err, "cannot encode %s: %v", target, err)
	}
	encodedLen, infoArgs, err := callInfoArgs(callBytes)
	if err != nil {
		return FeeEstimate{}, err
	}

	view, err := client.snapshot(f.pin)
	if err != nil {
		return FeeEstimate{}, err
	}
	rawInfo, err := view.call(apiQueryCallInfo, infoArgs)
	if err != nil {
		return FeeEstimate{}, err
	}
	info, err := decodeDispatchInfo(rawInfo)
	if err != nil {
		return FeeEstimate{}, err
	}
	prefix := client.properties.SS58Prefix
	call := priced{pallet: pallet, call: method, encodedLen: encodedLen, wrappedInProxy: delegation != nil}
	signer := client.AccountID()
	if signer == nil {
		return decodeEstimate(call, info, nil, prefix)
	}
	address := newAddress(signer, prefix)
	call.signer = &address
	// The payer depends on the fee, so this is asked second.
	payerArgs, err := feePayerArgs(signer, callBytes, info.partialFee)
	if err != nil {
		return FeeEstimate{}, err
	}
	payer, err := view.call(apiFeePayer, payerArgs)
	if err != nil {
		return FeeEstimate{}, err
	}
	return decodeEstimate(call, info, payer, prefix)
}

// NetworkFacade reads which chain this is, its blocks, its timing, and the health
// of the node answering. Reads only. Head reads at the latest finalized block
// unless pinned with At; the other reads are not about one block.
type NetworkFacade struct {
	client *MatterClient
	pin    *[blockHashBytes]byte
}

// Network returns the network façade.
func (c *MatterClient) Network() NetworkFacade { return NetworkFacade{client: c} }

// At makes Head describe block (a block hash) instead of the latest finalized
// block.
func (f NetworkFacade) At(block [32]byte) NetworkFacade {
	return NetworkFacade{client: f.client, pin: &block}
}

// Info reports which chain this is: its name, genesis hash, token and address
// format, as read once at connect. No request is made.
func (f NetworkFacade) Info() NetworkInfo { return networkInfo(f.client.properties) }

// headerAt reads the header of the block view reads at.
func headerAt(view snapshot) (BlockHeader, error) {
	var header *headerWire
	if err := view.requestHere(&header, rpcGetHeader); err != nil {
		return BlockHeader{}, err
	}
	return decodeHeader(view.at, header)
}

// Head reports the latest finalized block, or the pinned one: its height, hash,
// time and runtime version. Its Hash is what a façade's At takes, to make several
// reads share this block.
func (f NetworkFacade) Head() (Block, error) {
	view, err := f.client.snapshot(f.pin)
	if err != nil {
		return Block{}, err
	}
	header, err := headerAt(view)
	if err != nil {
		return Block{}, err
	}
	values, err := view.storage(nowRequest())
	if err != nil {
		return Block{}, err
	}
	var version runtimeVersionWire
	if err := view.requestHere(&version, rpcGetRuntimeVersion); err != nil {
		return Block{}, err
	}
	return decodeBlock(header, values[0], version)
}

// Block reports the block at height number, or nil if the chain has not reached
// it. It is read from headers alone, so it works for blocks whose state the node
// has pruned; At(hash).Head() adds the time and runtime version where it has not.
func (f NetworkFacade) Block(number uint64) (*BlockHeader, error) {
	var found *string
	if err := f.client.request(&found, rpcGetBlockHash, blockNumberParam(number)); err != nil {
		return nil, err
	}
	if found == nil {
		return nil, nil
	}
	hash, err := hashFromHex(rpcGetBlockHash, *found)
	if err != nil {
		return nil, err
	}
	header, err := headerAt(snapshot{client: f.client, at: hash})
	if err != nil {
		return nil, err
	}
	return &header, nil
}

// Node reports the node answering this client: its software, peers, whether it is
// still syncing, and its best and finalized blocks. It is about the node, not a
// block, so a pin does not apply.
func (f NetworkFacade) Node() (NodeStatus, error) {
	var name, version, bestHash string
	var health healthWire
	if err := f.client.request(&name, rpcSystemName); err != nil {
		return NodeStatus{}, err
	}
	if err := f.client.request(&version, rpcSystemVersion); err != nil {
		return NodeStatus{}, err
	}
	if err := f.client.request(&health, rpcSystemHealth); err != nil {
		return NodeStatus{}, err
	}
	if err := f.client.request(&bestHash, rpcGetBlockHash); err != nil {
		return NodeStatus{}, err
	}
	hash, err := hashFromHex(rpcGetBlockHash, bestHash)
	if err != nil {
		return NodeStatus{}, err
	}
	best, err := headerAt(snapshot{client: f.client, at: hash})
	if err != nil {
		return NodeStatus{}, err
	}
	finalizedView, err := f.client.snapshot(nil)
	if err != nil {
		return NodeStatus{}, err
	}
	finalized, err := headerAt(finalizedView)
	if err != nil {
		return NodeStatus{}, err
	}
	return nodeStatus(name, version, health, best, finalized)
}

// Timing reports how the chain measures time: its block time, and the length of a
// session, an era and the unbonding period. These are constants of the connected
// runtime; no request is made.
func (f NetworkFacade) Timing() (NetworkTiming, error) {
	constants := make([][]byte, len(timingConstants))
	for i, constant := range timingConstants {
		raw, err := f.client.chain.Constant(constant.pallet, constant.name)
		if err != nil {
			return NetworkTiming{}, err
		}
		constants[i] = raw
	}
	return decodeTiming(constants)
}

// SecretsFacade covers pallet-secrets: store, rotate, share, and delete.
type SecretsFacade struct{ client *MatterClient }

// Secrets returns the secrets façade.
func (c *MatterClient) Secrets() SecretsFacade { return SecretsFacade{c} }

// Store publishes a sealed envelope. The chain-assigned id is in the
// Secrets.SecretStored event; ChainClient.FindStoredSecret reads it back.
func (f SecretsFacade) Store(env EncryptedSecret, epoch uint32, label string, aad Aad) (TxReceipt, error) {
	return f.client.call("Secrets", "store_secret",
		newSecretsPayload(env), types.NewU32(epoch),
		types.NewBytes([]byte(label)), types.NewBytes(AadBytes(aad)))
}

// Rotate re-seals an existing secret in place under the current epoch.
func (f SecretsFacade) Rotate(id SecretID, env EncryptedSecret, epoch uint32, aad Aad) (TxReceipt, error) {
	return f.client.call("Secrets", "rotate_secret",
		types.NewU128(*id.BigInt()), newSecretsPayload(env),
		types.NewU32(epoch), types.NewBytes(AadBytes(aad)))
}

// Grant authorizes a principal to request decryption.
func (f SecretsFacade) Grant(id SecretID, target GrantTarget) (TxReceipt, error) {
	encoded, err := target.encode()
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Secrets", "grant_access", types.NewU128(*id.BigInt()), encoded)
}

// Revoke withdraws a grant. The target must match the grant exactly, or this is a
// no-op on chain.
func (f SecretsFacade) Revoke(id SecretID, target GrantTarget) (TxReceipt, error) {
	encoded, err := target.encode()
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Secrets", "revoke_access", types.NewU128(*id.BigInt()), encoded)
}

// Delete removes a secret and every grant on it. Owner only, and irreversible.
func (f SecretsFacade) Delete(id SecretID) (TxReceipt, error) {
	return f.client.call("Secrets", "delete_secret", types.NewU128(*id.BigInt()))
}

// DeploymentsFacade covers pallet-jobs: request compute, wire networking, bind secrets.
type DeploymentsFacade struct{ client *MatterClient }

// Deployments returns the deployments façade.
func (c *MatterClient) Deployments() DeploymentsFacade { return DeploymentsFacade{c} }

// Request requests a deployment. `request` is the runtime's ResourceRequest,
// passed through rather than mirrored.
func (f DeploymentsFacade) Request(request any) (TxReceipt, error) {
	return f.client.call("Jobs", "request_deployment", request)
}

// Cancel cancels a deployment.
func (f DeploymentsFacade) Cancel(deployment SecretID) (TxReceipt, error) {
	return f.client.call("Jobs", "cancel_deployment", types.NewU128(*deployment.BigInt()))
}

// SetSecretRef points a deployment at a secret, or clears it with nil. The
// assigned resource is authorized to decrypt whatever secretRef names.
func (f DeploymentsFacade) SetSecretRef(deployment SecretID, secretRef *SecretID) (TxReceipt, error) {
	return f.client.call("Jobs", "set_deployment_secret_ref",
		types.NewU128(*deployment.BigInt()), optionU128(secretRef))
}

// SetEnv sets or clears a deployment's plaintext environment variables. Anything
// sensitive belongs in a sealed secret referenced by SetSecretRef.
func (f DeploymentsFacade) SetEnv(deployment SecretID, envVars any) (TxReceipt, error) {
	return f.client.call("Jobs", "set_deployment_env",
		types.NewU128(*deployment.BigInt()), envVars)
}

// RegisterWgPeer registers a WireGuard peer public key against a deployment.
//
// pqCiphertext is the ML-KEM-768 ciphertext (1088 bytes) the peer
// encapsulated to the provider's on-chain ML-KEM key
// (OverlayNetworks.PqKemPubkeys); the provider decapsulates it to derive the
// tunnel's post-quantum preshared key. Requires runtime spec >= 330.
func (f DeploymentsFacade) RegisterWgPeer(deployment SecretID, pubkey [32]byte, pqCiphertext []byte) (TxReceipt, error) {
	return f.client.call("Jobs", "register_wg_peer",
		types.NewU128(*deployment.BigInt()), pubkey, types.Bytes(pqCiphertext))
}

// ResourcesFacade covers pallet-resources: register capacity, price it, control access.
type ResourcesFacade struct{ client *MatterClient }

// Resources returns the resources façade.
func (c *MatterClient) Resources() ResourcesFacade { return ResourcesFacade{c} }

// Register registers a resource you operate.
func (f ResourcesFacade) Register(resourceID []byte, ownershipProof any, name string) (TxReceipt, error) {
	resource, err := accountArg("resource id", resourceID)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Resources", "register_resource",
		resource, ownershipProof, types.NewBytes([]byte(name)))
}

// UpdateSku publishes or updates a SKU's pricing.
func (f ResourcesFacade) UpdateSku(uuid SecretID, sku any) (TxReceipt, error) {
	return f.client.call("Resources", "update_sku", types.NewU128(*uuid.BigInt()), sku)
}

// ReportCapacity reports current capacity.
func (f ResourcesFacade) ReportCapacity(capacity any) (TxReceipt, error) {
	return f.client.call("Resources", "report_capacity", capacity)
}

// SetPrivacy makes a resource private (whitelist-only) or public.
func (f ResourcesFacade) SetPrivacy(resourceID []byte, isPrivate bool) (TxReceipt, error) {
	resource, err := accountArg("resource id", resourceID)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Resources", "set_resource_privacy", resource, types.NewBool(isPrivate))
}

// Allow permits an account to use a private resource.
func (f ResourcesFacade) Allow(resourceID, user []byte) (TxReceipt, error) {
	return f.whitelist("add_to_whitelist", resourceID, user)
}

// Disallow withdraws a private resource's whitelist entry.
func (f ResourcesFacade) Disallow(resourceID, user []byte) (TxReceipt, error) {
	return f.whitelist("remove_from_whitelist", resourceID, user)
}

func (f ResourcesFacade) whitelist(method string, resourceID, user []byte) (TxReceipt, error) {
	resource, err := accountArg("resource id", resourceID)
	if err != nil {
		return TxReceipt{}, err
	}
	account, err := accountArg("user", user)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Resources", method, resource, account)
}

// StakingFacade covers the standard FRAME staking surface. Amounts are plancks;
// use MatterClient.ParseAmount rather than a hand-written exponent.
// pallet-staking-gateway (Ethereum meta-transactions) is out of scope.
type StakingFacade struct{ client *MatterClient }

// Staking returns the staking façade.
func (c *MatterClient) Staking() StakingFacade { return StakingFacade{c} }

// Bond bonds funds and sets a reward destination.
func (f StakingFacade) Bond(value *big.Int, payee any) (TxReceipt, error) {
	return f.client.call("Staking", "bond", types.NewUCompact(value), payee)
}

// BondExtra adds to an existing bond.
func (f StakingFacade) BondExtra(maxAdditional *big.Int) (TxReceipt, error) {
	return f.client.call("Staking", "bond_extra", types.NewUCompact(maxAdditional))
}

// Unbond schedules an unbond. Funds stay locked until the unbonding period elapses
// and WithdrawUnbonded is called.
func (f StakingFacade) Unbond(value *big.Int) (TxReceipt, error) {
	return f.client.call("Staking", "unbond", types.NewUCompact(value))
}

// WithdrawUnbonded moves unlocked funds back to free balance.
func (f StakingFacade) WithdrawUnbonded(numSlashingSpans uint32) (TxReceipt, error) {
	return f.client.call("Staking", "withdraw_unbonded", types.NewU32(numSlashingSpans))
}

// Nominate nominates validators, by 32-byte account id.
func (f StakingFacade) Nominate(targets [][]byte) (TxReceipt, error) {
	addresses := make([]types.MultiAddress, 0, len(targets))
	for _, target := range targets {
		address, err := types.NewMultiAddressFromAccountID(target)
		if err != nil {
			return TxReceipt{}, fmt.Errorf("nominate target %s: %w", toHex(target), err)
		}
		addresses = append(addresses, address)
	}
	return f.client.call("Staking", "nominate", addresses)
}

// Chill stops nominating or validating.
func (f StakingFacade) Chill() (TxReceipt, error) {
	return f.client.call("Staking", "chill")
}

// JoinPool joins a nomination pool with `amount` plancks.
func (f StakingFacade) JoinPool(amount *big.Int, poolID uint32) (TxReceipt, error) {
	return f.client.call("NominationPools", "join", types.NewUCompact(amount), types.NewU32(poolID))
}

// ClaimPoolPayout claims accrued nomination-pool rewards.
func (f StakingFacade) ClaimPoolPayout() (TxReceipt, error) {
	return f.client.call("NominationPools", "claim_payout")
}

// OrgsFacade covers pallet-organizations and pallet-budgets.
type OrgsFacade struct{ client *MatterClient }

// Orgs returns the organizations façade.
func (c *MatterClient) Orgs() OrgsFacade { return OrgsFacade{c} }

// Create creates an organization. The runtime derives the org id from the
// signer and a sequence number.
func (f OrgsFacade) Create() (TxReceipt, error) {
	return f.client.call("Organizations", "create_org")
}

// AddMember adds a member with a role.
func (f OrgsFacade) AddMember(org [32]byte, who []byte, role any) (TxReceipt, error) {
	member, err := accountArg("member", who)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Organizations", "add_member", org, member, role)
}

// RemoveMember removes a member.
func (f OrgsFacade) RemoveMember(org [32]byte, who []byte) (TxReceipt, error) {
	member, err := accountArg("member", who)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Organizations", "remove_member", org, member)
}

// Allot allots budget from an org treasury to a project, in plancks.
func (f OrgsFacade) Allot(org, project [32]byte, amount *big.Int) (TxReceipt, error) {
	return f.client.call("Budgets", "allot", org, project, types.NewU128(*amount))
}

// AuthorizeSecretsAgent authorizes an account to decrypt a project's secrets — the
// org-scoped analogue of secrets.grant_access.
func (f OrgsFacade) AuthorizeSecretsAgent(org, project [32]byte, who []byte) (TxReceipt, error) {
	return f.secretsAgent("authorize_project_secrets_agent", org, project, who)
}

// RevokeSecretsAgent withdraws a project secrets-agent authorization.
func (f OrgsFacade) RevokeSecretsAgent(org, project [32]byte, who []byte) (TxReceipt, error) {
	return f.secretsAgent("revoke_project_secrets_agent", org, project, who)
}

func (f OrgsFacade) secretsAgent(method string, org, project [32]byte, who []byte) (TxReceipt, error) {
	agent, err := accountArg("secrets agent", who)
	if err != nil {
		return TxReceipt{}, err
	}
	return f.client.call("Budgets", method, org, project, agent)
}

// accountArg encodes a 32-byte account id as the runtime's AccountId32. A bare
// []byte would be SCALE-encoded with a length prefix, which the runtime rejects.
func accountArg(field string, id []byte) (types.AccountID, error) {
	account, err := types.NewAccountID(id)
	if err != nil {
		return types.AccountID{}, fmt.Errorf("%s: %w", field, err)
	}
	return *account, nil
}

// optionU128 renders an optional u128 as the runtime's Option enum.
func optionU128(value *SecretID) []byte {
	if value == nil {
		return []byte{0x00} // None
	}
	le := value.LEBytes()
	return append([]byte{0x01}, le[:]...) // Some(u128)
}

// KeysFacade covers pallet-budgets' roster calls: minting and revoking
// member-tied API keys. They are never admitted to a key, so use a client built
// on a human seed or HSM signer; a delegated client is refused before submission.
type KeysFacade struct{ client *MatterClient }

// Keys returns the keys façade.
func (c *MatterClient) Keys() KeysFacade { return KeysFacade{c} }

// Authorize registers key as an API key acting for the signer, with scopes. An
// upsert, so it also re-scopes a live key.
func (f KeysFacade) Authorize(key []byte, scopes ScopeSet) (TxReceipt, error) {
	account, err := types.NewAccountID(key)
	if err != nil {
		return TxReceipt{}, fmt.Errorf("api key account id: %w", err)
	}
	return f.client.call("Budgets", "authorize_agent_key",
		*account, types.NewU32(scopes.Bits()))
}

// Revoke withdraws key's authority — and its committee decrypt rights — from the
// next request onward.
func (f KeysFacade) Revoke(key []byte) (TxReceipt, error) {
	account, err := types.NewAccountID(key)
	if err != nil {
		return TxReceipt{}, fmt.Errorf("api key account id: %w", err)
	}
	return f.client.call("Budgets", "revoke_agent_key", *account)
}

// Lookup reports who key acts for and what it may do, or nil if it is not
// registered. A read, so it needs no signer and works on a read-only client.
func (f KeysFacade) Lookup(key []byte) (*Delegation, error) {
	return f.client.AgentKey(key)
}
