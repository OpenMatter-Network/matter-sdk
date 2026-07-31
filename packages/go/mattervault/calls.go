package mattervault

// Ready-to-submit on-chain call arguments for pallet-secrets.
//
// Go previously had no call builders at all — StoreSecret assembled its arguments
// inline, and the other four pallet-secrets calls were unreachable. These give the
// remaining calls a home, and give GrantTarget one shape shared with Rust,
// TypeScript, and Python.

import (
	"fmt"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// GrantTargetKind distinguishes the runtime's GrantTarget variants.
type GrantTargetKind uint8

const (
	// GrantUser names another user or a resource node by account.
	GrantUser GrantTargetKind = 0
	// GrantDeployment names a deployment, authorizing whichever resource is
	// currently assigned to it — so the owner need not name an account that only
	// exists after assignment.
	GrantDeployment GrantTargetKind = 1
)

// GrantTarget is who a secret is granted to.
//
// The chain's GrantTarget<AccountId> is an enum, not a bare account id. Earlier
// call builders in the other bindings emitted a raw 32-byte grantee, which the
// runtime cannot decode — the call data was dead on arrival, and nothing caught it
// because no end-to-end test exercised grant.
type GrantTarget struct {
	Kind GrantTargetKind
	// Account is set when Kind is GrantUser.
	Account []byte
	// Deployment is set when Kind is GrantDeployment.
	Deployment SecretID
}

// UserTarget builds a grant target naming an account.
func UserTarget(account []byte) (GrantTarget, error) {
	if len(account) != accountIDBytes {
		return GrantTarget{}, fmt.Errorf("account must be %d bytes, got %d", accountIDBytes, len(account))
	}
	return GrantTarget{Kind: GrantUser, Account: account}, nil
}

// DeploymentTarget builds a grant target naming a deployment.
func DeploymentTarget(deployment SecretID) GrantTarget {
	return GrantTarget{Kind: GrantDeployment, Deployment: deployment}
}

// String renders the target for logs and errors.
func (t GrantTarget) String() string {
	if t.Kind == GrantUser {
		return fmt.Sprintf("User(%s)", toHex(t.Account))
	}
	return fmt.Sprintf("Deployment(%s)", t.Deployment)
}

// encode renders the target as the SCALE enum the runtime decodes: a one-byte
// variant index followed by the variant's payload.
func (t GrantTarget) encode() ([]byte, error) {
	switch t.Kind {
	case GrantUser:
		if len(t.Account) != accountIDBytes {
			return nil, fmt.Errorf("grant target account must be %d bytes", accountIDBytes)
		}
		return append([]byte{byte(GrantUser)}, t.Account...), nil
	case GrantDeployment:
		le := t.Deployment.LEBytes()
		return append([]byte{byte(GrantDeployment)}, le[:]...), nil
	default:
		return nil, fmt.Errorf("unknown grant target kind %d", t.Kind)
	}
}

// secretsPayload is the runtime's EncryptedSecret composite.
type secretsPayload struct {
	BindingID types.Bytes
	Capsule   types.Bytes
	Proof     types.Bytes
	CT        types.Bytes
}

func newSecretsPayload(env EncryptedSecret) secretsPayload {
	return secretsPayload{
		BindingID: types.NewBytes(env.BindingID),
		Capsule:   types.NewBytes(env.Capsule),
		Proof:     types.NewBytes(env.Proof),
		CT:        types.NewBytes(env.CT),
	}
}

// StoreSecretCall builds `Secrets.store_secret(payload, epoch, label, aad)`.
func (c *ChainClient) StoreSecretCall(env EncryptedSecret, epoch uint32, label string, aad Aad) (types.Call, error) {
	return types.NewCall(
		c.meta,
		"Secrets.store_secret",
		newSecretsPayload(env),
		types.NewU32(epoch),
		types.NewBytes([]byte(label)),
		types.NewBytes(AadBytes(aad)),
	)
}

// RotateSecretCall builds `Secrets.rotate_secret(secret_id, payload, epoch, aad)`.
func (c *ChainClient) RotateSecretCall(id SecretID, env EncryptedSecret, epoch uint32, aad Aad) (types.Call, error) {
	return types.NewCall(
		c.meta,
		"Secrets.rotate_secret",
		types.NewU128(*id.BigInt()),
		newSecretsPayload(env),
		types.NewU32(epoch),
		types.NewBytes(AadBytes(aad)),
	)
}

// GrantAccessCall builds `Secrets.grant_access(secret_id, target)`.
func (c *ChainClient) GrantAccessCall(id SecretID, target GrantTarget) (types.Call, error) {
	encoded, err := target.encode()
	if err != nil {
		return types.Call{}, err
	}
	return types.NewCall(c.meta, "Secrets.grant_access", types.NewU128(*id.BigInt()), encoded)
}

// RevokeAccessCall builds `Secrets.revoke_access(secret_id, target)`.
//
// The target must match the grant exactly, or the call is a no-op on chain.
func (c *ChainClient) RevokeAccessCall(id SecretID, target GrantTarget) (types.Call, error) {
	encoded, err := target.encode()
	if err != nil {
		return types.Call{}, err
	}
	return types.NewCall(c.meta, "Secrets.revoke_access", types.NewU128(*id.BigInt()), encoded)
}

// DeleteSecretCall builds `Secrets.delete_secret(secret_id)`. Owner only, and
// irreversible.
func (c *ChainClient) DeleteSecretCall(id SecretID) (types.Call, error) {
	return types.NewCall(c.meta, "Secrets.delete_secret", types.NewU128(*id.BigInt()))
}
