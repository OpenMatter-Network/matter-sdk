// Substrate chain client for the matter-kgc chain (GSRPC). Reads the committee
// context via runtime-API state_calls and submits the gas-paying
// secrets.store_secret extrinsic — the "your own Substrate client" half the SDK
// deliberately leaves to you, here built on go-substrate-rpc-client.
package mattervault

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

// ChainClient is a thin GSRPC wrapper over the matter-kgc chain.
type ChainClient struct {
	api  *gsrpc.SubstrateAPI
	meta *types.Metadata
}

// ChainNode is one committee node as read from chain.
type ChainNode struct {
	Account  []byte
	Index    uint64
	Endpoint string
}

// NewChainClient connects and loads metadata.
func NewChainClient(url string) (*ChainClient, error) {
	api, err := gsrpc.NewSubstrateAPI(url)
	if err != nil {
		return nil, err
	}
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}
	return &ChainClient{api: api, meta: meta}, nil
}

func (c *ChainClient) stateCall(method string, args []byte) ([]byte, error) {
	argHex := "0x"
	if len(args) > 0 {
		argHex = codec.HexEncodeToString(args)
	}
	var res string
	if err := c.api.Client.Call(&res, "state_call", method, argHex); err != nil {
		return nil, err
	}
	return codec.HexDecodeString(res)
}

func decodeOptionBytes(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	dec := scale.NewDecoder(bytes.NewReader(raw))
	flag, err := dec.ReadOneByte()
	if err != nil {
		return nil, err
	}
	if flag == 0 {
		return nil, nil
	}
	var b types.Bytes
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	return []byte(b), nil
}

// JointPk returns the committee joint public key.
func (c *ChainClient) JointPk() ([]byte, error) {
	raw, err := c.stateCall("KgcApi_joint_pk", nil)
	if err != nil {
		return nil, err
	}
	v, err := decodeOptionBytes(raw)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("KGC DKG not finalised on chain (joint_pk is None)")
	}
	return v, nil
}

// DkgEpoch returns the current DKG epoch.
func (c *ChainClient) DkgEpoch() (uint32, error) {
	raw, err := c.stateCall("KgcApi_dkg_epoch", nil)
	if err != nil {
		return 0, err
	}
	var e types.U32
	if err := scale.NewDecoder(bytes.NewReader(raw)).Decode(&e); err != nil {
		return 0, err
	}
	return uint32(e), nil
}

// SharedA returns the committee shared_a for the current epoch.
func (c *ChainClient) SharedA() ([]byte, error) {
	raw, err := c.stateCall("KgcApi_shared_a", nil)
	if err != nil {
		return nil, err
	}
	v, err := decodeOptionBytes(raw)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("KGC shared_a unavailable (DKG not finalised)")
	}
	return v, nil
}

// ThresholdAtEpoch returns the committee threshold t for an epoch.
func (c *ChainClient) ThresholdAtEpoch(epoch uint32) (int, error) {
	arg := make([]byte, 4)
	binary.LittleEndian.PutUint32(arg, epoch)
	raw, err := c.stateCall("KgcApi_threshold_params_at_epoch", arg)
	if err != nil {
		return 0, err
	}
	var t struct {
		A types.U64
		B types.U64
	}
	if err := scale.NewDecoder(bytes.NewReader(raw)).Decode(&t); err != nil {
		return 0, err
	}
	return int(t.B), nil
}

// Nodes returns the registered committee nodes.
func (c *ChainClient) Nodes() ([]ChainNode, error) {
	raw, err := c.stateCall("KgcApi_kgc_nodes", nil)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Account  types.AccountID
		Endpoint types.Bytes
		DkgIndex types.U64
	}
	if err := scale.NewDecoder(bytes.NewReader(raw)).Decode(&rows); err != nil {
		return nil, err
	}
	out := make([]ChainNode, len(rows))
	for i, r := range rows {
		acct := make([]byte, 32)
		copy(acct, r.Account[:])
		out[i] = ChainNode{Account: acct, Index: uint64(r.DkgIndex), Endpoint: normalizeEndpoint(string(r.Endpoint))}
	}
	return out, nil
}

// ShareCommitment returns a node's Feldman commitment for an epoch.
func (c *ChainClient) ShareCommitment(epoch uint32, account []byte) ([]byte, error) {
	arg := make([]byte, 4)
	binary.LittleEndian.PutUint32(arg, epoch)
	arg = append(arg, account...)
	raw, err := c.stateCall("KgcApi_share_commitment", arg)
	if err != nil {
		return nil, err
	}
	v, err := decodeOptionBytes(raw)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("missing share commitment for a node")
	}
	return v, nil
}

func secretIDArg(id uint64) []byte {
	arg := make([]byte, 16) // u128 little-endian
	binary.LittleEndian.PutUint64(arg[:8], id)
	return arg
}

// SecretPayload reads a stored secret's envelope from chain.
func (c *ChainClient) SecretPayload(id uint64) (*EncryptedSecret, error) {
	raw, err := c.stateCall("SecretsApi_secret_payload", secretIDArg(id))
	if err != nil {
		return nil, err
	}
	dec := scale.NewDecoder(bytes.NewReader(raw))
	flag, err := dec.ReadOneByte()
	if err != nil {
		return nil, err
	}
	if flag == 0 {
		return nil, fmt.Errorf("secret %d not found on chain", id)
	}
	var w struct {
		BindingID types.Bytes
		Capsule   types.Bytes
		Proof     types.Bytes
		CT        types.Bytes
	}
	if err := dec.Decode(&w); err != nil {
		return nil, err
	}
	return &EncryptedSecret{
		BindingID: []byte(w.BindingID),
		Capsule:   []byte(w.Capsule),
		Proof:     []byte(w.Proof),
		CT:        []byte(w.CT),
	}, nil
}

// SecretEpoch reads the epoch a stored secret was sealed under.
func (c *ChainClient) SecretEpoch(id uint64) (uint32, error) {
	raw, err := c.stateCall("SecretsApi_secret_epoch", secretIDArg(id))
	if err != nil {
		return 0, err
	}
	dec := scale.NewDecoder(bytes.NewReader(raw))
	flag, err := dec.ReadOneByte()
	if err != nil {
		return 0, err
	}
	if flag == 0 {
		return 0, fmt.Errorf("secret %d has no epoch", id)
	}
	var e types.U32
	if err := dec.Decode(&e); err != nil {
		return 0, err
	}
	return uint32(e), nil
}

// FinalizedHead returns the latest finalized block hash (the request freshness anchor).
func (c *ChainClient) FinalizedHead() ([32]byte, error) {
	var z [32]byte
	h, err := c.api.RPC.Chain.GetFinalizedHead()
	if err != nil {
		return z, err
	}
	copy(z[:], h[:])
	return z, nil
}

func (c *ChainClient) accountNonce(pubkey []byte) (uint32, error) {
	key, err := types.CreateStorageKey(c.meta, "System", "Account", pubkey)
	if err != nil {
		return 0, err
	}
	raw, err := c.api.RPC.State.GetStorageRawLatest(key)
	if err != nil {
		return 0, err
	}
	b := []byte(*raw)
	if len(b) < 4 {
		return 0, fmt.Errorf("account %x not found / unfunded", pubkey)
	}
	// AccountInfo starts with the u32 nonce (read it directly to avoid layout drift).
	return binary.LittleEndian.Uint32(b[:4]), nil
}

func (c *ChainClient) nextSecretID() (uint64, error) {
	key, err := types.CreateStorageKey(c.meta, "Secrets", "NextSecretId")
	if err != nil {
		return 0, err
	}
	raw, err := c.api.RPC.State.GetStorageRawLatest(key)
	if err != nil {
		return 0, err
	}
	b := []byte(*raw)
	if len(b) < 8 {
		return 0, nil
	}
	return binary.LittleEndian.Uint64(b[:8]), nil
}

func compactUint(v uint64) []byte {
	b, _ := codec.Encode(types.NewUCompactFromUInt(v))
	return b
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// StoreSecret submits secrets.store_secret and returns the chain-assigned id.
//
// The extrinsic is hand-assembled rather than built with GSRPC's signer: this
// runtime's signed extensions include CheckMetadataHash (and WeightReclaim),
// which GSRPC does not encode, so its signed payload is misaligned and the
// runtime rejects it. We add the CheckMetadataHash `mode = Disabled` byte to the
// extra and the matching `None` to the additional-signed data. After submission
// we poll the finalized head until the secret is readable, so a subsequent
// decrypt sees it as authorized (the committee checks a finalized block).
func (c *ChainClient) StoreSecret(kp signature.KeyringPair, env EncryptedSecret, epoch uint32, aad Aad) (uint64, error) {
	payload := struct {
		BindingID types.Bytes
		Capsule   types.Bytes
		Proof     types.Bytes
		CT        types.Bytes
	}{types.NewBytes(env.BindingID), types.NewBytes(env.Capsule), types.NewBytes(env.Proof), types.NewBytes(env.CT)}

	call, err := types.NewCall(c.meta, "Secrets.store_secret", payload, types.NewU32(epoch), types.NewBytes([]byte{}), types.NewBytes(AadBytes(aad)))
	if err != nil {
		return 0, err
	}
	callBytes, err := codec.Encode(call)
	if err != nil {
		return 0, err
	}

	genesis, err := c.api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		return 0, err
	}
	rv, err := c.api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return 0, err
	}
	nonce, err := c.accountNonce(kp.PublicKey)
	if err != nil {
		return 0, err
	}
	predicted, err := c.nextSecretID()
	if err != nil {
		return 0, err
	}

	// extra (per-extension, in metadata order): Era(immortal) ++ Compact(nonce)
	// ++ Compact(tip=0) ++ CheckMetadataHash mode(Disabled).
	extra := []byte{0x00}
	extra = append(extra, compactUint(uint64(nonce))...)
	extra = append(extra, compactUint(0)...)
	extra = append(extra, 0x00)

	// additionalSigned: SpecVersion ++ TxVersion ++ Genesis ++ Mortality-anchor
	// (genesis for immortal) ++ CheckMetadataHash None.
	additional := append([]byte{}, u32le(uint32(rv.SpecVersion))...)
	additional = append(additional, u32le(uint32(rv.TransactionVersion))...)
	additional = append(additional, genesis[:]...)
	additional = append(additional, genesis[:]...)
	additional = append(additional, 0x00)

	signingPayload := append(append(append([]byte{}, callBytes...), extra...), additional...)
	sig, err := signature.Sign(signingPayload, kp.URI) // blake2-hashes >256B, then sr25519
	if err != nil {
		return 0, err
	}

	// Assemble the signed extrinsic: version(0x84) ++ MultiAddress::Id(account)
	// ++ MultiSignature::Sr25519(sig) ++ extra ++ call, length-prefixed.
	body := []byte{0x84, 0x00}
	body = append(body, kp.PublicKey...)
	body = append(body, 0x01)
	body = append(body, sig...)
	body = append(body, extra...)
	body = append(body, callBytes...)
	full := append(compactUint(uint64(len(body))), body...)

	var txHash string
	if err := c.api.Client.Call(&txHash, "author_submitExtrinsic", "0x"+hex.EncodeToString(full)); err != nil {
		return 0, err
	}

	// Poll the finalized head until the secret is readable there.
	for i := 0; i < 40; i++ {
		time.Sleep(3 * time.Second)
		fin, err := c.api.RPC.Chain.GetFinalizedHead()
		if err != nil {
			continue
		}
		if ok, _ := c.secretExistsAt(fin, predicted); ok {
			return predicted, nil
		}
	}
	return 0, fmt.Errorf("store submitted (tx %s) but secret %d was not finalized in time", txHash, predicted)
}

func (c *ChainClient) secretExistsAt(at types.Hash, id uint64) (bool, error) {
	var res string
	argHex := codec.HexEncodeToString(secretIDArg(id))
	if err := c.api.Client.Call(&res, "state_call", "SecretsApi_secret_payload", argHex, codec.HexEncodeToString(at[:])); err != nil {
		return false, err
	}
	raw, err := codec.HexDecodeString(res)
	if err != nil {
		return false, err
	}
	return len(raw) > 0 && raw[0] != 0, nil // Option::Some
}

func normalizeEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}
