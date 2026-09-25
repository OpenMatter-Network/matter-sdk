package mattersdk

// Typed façades: thin named wrappers over MatterClient.Call. Anything not here is
// one client.Call or client.Tx away.
//
// Names resolve at call time from live metadata. testvectors/facade_calls.json and
// facade_test.go pin the surface both ways: a fixture row without a method fails,
// and a method without a row fails.
//
// Every write waits for finalization and returns a TxReceipt. Under a member-tied
// key, a call refused inside proxy.proxy is a ChainError of KindDispatch, never a
// receipt.

import (
	"fmt"
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
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

// call is Call for the façades.
func (c *MatterClient) call(pallet, method string, args ...any) (TxReceipt, error) {
	return c.Call(pallet, method, args...)
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
	return f.client.call("Resources", "register_resource",
		resourceID, ownershipProof, types.NewBytes([]byte(name)))
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
	return f.client.call("Resources", "set_resource_privacy", resourceID, types.NewBool(isPrivate))
}

// Allow permits an account to use a private resource.
func (f ResourcesFacade) Allow(resourceID, user []byte) (TxReceipt, error) {
	return f.client.call("Resources", "add_to_whitelist", resourceID, user)
}

// Disallow withdraws a private resource's whitelist entry.
func (f ResourcesFacade) Disallow(resourceID, user []byte) (TxReceipt, error) {
	return f.client.call("Resources", "remove_from_whitelist", resourceID, user)
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
	return f.client.call("Organizations", "add_member", org, who, role)
}

// RemoveMember removes a member.
func (f OrgsFacade) RemoveMember(org [32]byte, who []byte) (TxReceipt, error) {
	return f.client.call("Organizations", "remove_member", org, who)
}

// Allot allots budget from an org treasury to a project, in plancks.
func (f OrgsFacade) Allot(org, project [32]byte, amount *big.Int) (TxReceipt, error) {
	return f.client.call("Budgets", "allot", org, project, types.NewUCompact(amount))
}

// AuthorizeSecretsAgent authorizes an account to decrypt a project's secrets — the
// org-scoped analogue of secrets.grant_access.
func (f OrgsFacade) AuthorizeSecretsAgent(org, project [32]byte, who []byte) (TxReceipt, error) {
	return f.client.call("Budgets", "authorize_project_secrets_agent", org, project, who)
}

// RevokeSecretsAgent withdraws a project secrets-agent authorization.
func (f OrgsFacade) RevokeSecretsAgent(org, project [32]byte, who []byte) (TxReceipt, error) {
	return f.client.call("Budgets", "revoke_project_secrets_agent", org, project, who)
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
