package mattersdk

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// capturingClient builds façade calls against the spec-330 metadata and captures
// them instead of submitting.
func capturingClient(t *testing.T) (*MatterClient, *types.Call) {
	t.Helper()
	captured := &types.Call{}
	client := &MatterClient{
		chain: &ChainClient{meta: loadSpec322Metadata(t)},
		submitCall: func(call types.Call) (TxReceipt, error) {
			*captured = call
			return TxReceipt{}, nil
		},
	}
	return client, captured
}

// decodesExactly reports whether the call's arguments decode against the runtime's
// declared field types and consume every byte: a length-prefixed account or a
// compact where the runtime wants a fixed-width integer fails one or the other.
func decodesExactly(t *testing.T, meta *types.Metadata, call types.Call) {
	t.Helper()
	calls, err := registry.NewFactory().CreateCallRegistry(meta)
	if err != nil {
		t.Fatalf("build the call registry: %v", err)
	}
	reader := bytes.NewReader(call.Args)
	if _, err := calls[call.CallIndex].Decode(scale.NewDecoder(reader)); err != nil {
		t.Fatalf("arguments do not decode as the runtime declares them: %v", err)
	}
	if reader.Len() != 0 {
		t.Fatalf("%d trailing bytes: an argument is wider than the runtime declares", reader.Len())
	}
}

func TestFacadeAccountAndAmountArgumentsMatchTheRuntime(t *testing.T) {
	var org, project [32]byte
	account := bytes.Repeat([]byte{7}, 32)
	role := types.NewU8(2) // Role::Member

	cases := map[string]func(*MatterClient) (TxReceipt, error){
		"Resources.set_resource_privacy": func(c *MatterClient) (TxReceipt, error) {
			return c.Resources().SetPrivacy(account, true)
		},
		"Resources.add_to_whitelist": func(c *MatterClient) (TxReceipt, error) {
			return c.Resources().Allow(account, account)
		},
		"Resources.remove_from_whitelist": func(c *MatterClient) (TxReceipt, error) {
			return c.Resources().Disallow(account, account)
		},
		"Organizations.add_member": func(c *MatterClient) (TxReceipt, error) {
			return c.Orgs().AddMember(org, account, role)
		},
		"Organizations.remove_member": func(c *MatterClient) (TxReceipt, error) {
			return c.Orgs().RemoveMember(org, account)
		},
		"Budgets.allot": func(c *MatterClient) (TxReceipt, error) {
			return c.Orgs().Allot(org, project, big.NewInt(100))
		},
		"Budgets.authorize_project_secrets_agent": func(c *MatterClient) (TxReceipt, error) {
			return c.Orgs().AuthorizeSecretsAgent(org, project, account)
		},
		"Budgets.revoke_project_secrets_agent": func(c *MatterClient) (TxReceipt, error) {
			return c.Orgs().RevokeSecretsAgent(org, project, account)
		},
	}
	for target, submit := range cases {
		t.Run(target, func(t *testing.T) {
			client, captured := capturingClient(t)
			if _, err := submit(client); err != nil {
				t.Fatalf("build %s: %v", target, err)
			}
			decodesExactly(t, client.chain.meta, *captured)
		})
	}
}

func TestAFacadeRefusesAnAccountThatIsNot32Bytes(t *testing.T) {
	client, _ := capturingClient(t)
	if _, err := client.Resources().Allow(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("a 31-byte resource id must be refused, not encoded")
	}
	if _, err := client.Orgs().RemoveMember([32]byte{}, make([]byte, 33)); err == nil {
		t.Fatal("a 33-byte member id must be refused, not encoded")
	}
}
