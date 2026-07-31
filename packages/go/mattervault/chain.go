// Substrate chain client for MatterChain, built on go-substrate-rpc-client.
//
// Reads the committee context via runtime-API state_calls, and signs and submits
// extrinsics — any pallet the runtime exposes, resolved by name from the metadata
// loaded at connect. See generic.go for the untyped read surface and extrinsic.go
// for why the signed extrinsic is assembled by hand.
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

// How long StoreSecret waits for the stored secret to appear at the finalized
// head: 40 attempts × 3s = 2 minutes.
const (
	storeFinalityAttempts = 40
	storeFinalityInterval = 3 * time.Second
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

// Close releases the underlying websocket connection.
func (c *ChainClient) Close() {
	if c.api != nil && c.api.Client != nil {
		c.api.Client.Close()
	}
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

// secretIDArg renders a secret id as the SCALE u128 argument a runtime API takes.
func secretIDArg(id SecretID) []byte {
	arg := id.LEBytes()
	return arg[:]
}

// SecretPayload reads a stored secret's envelope from chain.
func (c *ChainClient) SecretPayload(id SecretID) (*EncryptedSecret, error) {
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
		return nil, fmt.Errorf("secret %s not found on chain", id)
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
func (c *ChainClient) SecretEpoch(id SecretID) (uint32, error) {
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
		return 0, fmt.Errorf("secret %s has no epoch", id)
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

// NextSecretID reads the `Secrets.NextSecretId` counter — a u128 stored
// little-endian. Useful as a rough count of secrets ever stored.
//
// Do NOT use it to predict the id a store will be assigned. StoreSecret used to do
// exactly that, and it is a race: two concurrent submitters read the same value, so
// confirming "id N exists" can pass on someone else's secret. Read the id from the
// `Secrets.SecretStored` event instead — see FindStoredSecret.
func (c *ChainClient) NextSecretID() (SecretID, error) {
	key, err := types.CreateStorageKey(c.meta, "Secrets", "NextSecretId")
	if err != nil {
		return SecretID{}, err
	}
	raw, err := c.api.RPC.State.GetStorageRawLatest(key)
	if err != nil {
		return SecretID{}, err
	}
	b := []byte(*raw)
	if len(b) < 16 {
		// An unset counter reads as empty (or short) storage: the next id is 0.
		return SecretID{}, nil
	}
	var le [16]byte
	copy(le[:], b[:16])
	// Reverse to big-endian, which is what SecretIDFromBytes takes.
	var be [16]byte
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return SecretIDFromBytes(be), nil
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

// ExtrinsicSigner is what SubmitCall needs from a key holder: an on-chain
// identity, and a way to sign the exact bytes it is handed.
//
// The payload arrives already blake2b-hashed when oversized (see
// UnsignedExtrinsic.SigningPayload), so an implementation only has to produce a
// raw sr25519 signature — it must not hash again.
type ExtrinsicSigner interface {
	AccountID() []byte
	SignExtrinsic(payload []byte) ([]byte, error)
}

// KeyringSigner adapts a GSRPC KeyringPair to ExtrinsicSigner, for callers that
// already hold one.
type KeyringSigner struct{ Pair signature.KeyringPair }

// AccountID returns the pair's 32-byte public key.
func (k KeyringSigner) AccountID() []byte { return k.Pair.PublicKey }

// SignExtrinsic signs with the pair's URI.
//
// `signature.Sign` blake2-hashes payloads over 256 bytes, and our caller has
// already done so; re-hashing would produce a signature over the wrong bytes.
// Passing an already-hashed 32-byte digest is below that threshold, so it is
// signed verbatim — which is exactly what the runtime verifies.
func (k KeyringSigner) SignExtrinsic(payload []byte) ([]byte, error) {
	return signature.Sign(payload, k.Pair.URI)
}

// SubmitCall signs and submits any call, returning the transaction hash.
//
// Assembly walks the signed extensions the runtime's metadata declares rather
// than assuming a fixed layout — see extrinsic.go for why. This is the single
// submission path; every typed helper is a caller.
func (c *ChainClient) SubmitCall(signer ExtrinsicSigner, call types.Call) (string, error) {
	ctx, err := c.signingContext(signer.AccountID())
	if err != nil {
		return "", err
	}
	unsigned, err := PrepareExtrinsic(c.meta, call, ctx)
	if err != nil {
		return "", err
	}
	sig, err := signer.SignExtrinsic(unsigned.SigningPayload())
	if err != nil {
		return "", fmt.Errorf("sign extrinsic: %w", err)
	}
	full, err := unsigned.Assemble(signer.AccountID(), sig)
	if err != nil {
		return "", err
	}

	var txHash string
	if err := c.api.Client.Call(&txHash, "author_submitExtrinsic", "0x"+hex.EncodeToString(full)); err != nil {
		return "", fmt.Errorf("submit extrinsic: %w", err)
	}
	return txHash, nil
}

// signingContext gathers the chain and account state the signed extensions need.
func (c *ChainClient) signingContext(accountID []byte) (SigningContext, error) {
	var ctx SigningContext

	genesis, err := c.api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		return ctx, fmt.Errorf("genesis hash: %w", err)
	}
	rv, err := c.api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return ctx, fmt.Errorf("runtime version: %w", err)
	}
	nonce, err := c.accountNonce(accountID)
	if err != nil {
		return ctx, err
	}

	ctx.SpecVersion = uint32(rv.SpecVersion)
	ctx.TransactionVersion = uint32(rv.TransactionVersion)
	copy(ctx.GenesisHash[:], genesis[:])
	// Immortal era: the mortality anchor is the genesis hash.
	ctx.MortalityHash = ctx.GenesisHash
	ctx.Nonce = nonce
	return ctx, nil
}

// StoreSecret submits secrets.store_secret and returns the chain-assigned id.
//
// After submission it polls the finalized head until the secret is readable
// there, so a subsequent decrypt sees it as authorized — the committee checks a
// finalized block, and resolving earlier yields an HTTP 403.
func (c *ChainClient) StoreSecret(kp signature.KeyringPair, env EncryptedSecret, epoch uint32, aad Aad) (SecretID, error) {
	payload := struct {
		BindingID types.Bytes
		Capsule   types.Bytes
		Proof     types.Bytes
		CT        types.Bytes
	}{types.NewBytes(env.BindingID), types.NewBytes(env.Capsule), types.NewBytes(env.Proof), types.NewBytes(env.CT)}

	call, err := types.NewCall(c.meta, "Secrets.store_secret", payload, types.NewU32(epoch), types.NewBytes([]byte{}), types.NewBytes(AadBytes(aad)))
	if err != nil {
		return SecretID{}, err
	}

	txHash, err := c.SubmitCall(KeyringSigner{Pair: kp}, call)
	if err != nil {
		return SecretID{}, err
	}

	// Take the id from the chain's own `Secrets.SecretStored` event, matched on our
	// account. This replaces reading the `NextSecretId` counter before submitting:
	// two concurrent submitters read the same counter, so that was a prediction
	// that could confirm someone else's secret.
	//
	// Scanning each newly finalized block also gives finality for free, which the
	// committee requires — it authorizes a partial-decrypt against the finalized
	// head, so acting earlier yields an HTTP 403.
	var lastScanned types.Hash
	for i := 0; i < storeFinalityAttempts; i++ {
		time.Sleep(storeFinalityInterval)
		fin, err := c.api.RPC.Chain.GetFinalizedHead()
		if err != nil || fin == lastScanned {
			continue
		}
		lastScanned = fin

		id, found, err := c.FindStoredSecret(fin, kp.PublicKey)
		if err != nil {
			// A decode failure on one block should not abandon the store: the
			// extrinsic may land in the next one.
			continue
		}
		if found {
			return id, nil
		}
	}
	return SecretID{}, fmt.Errorf(
		"store submitted (tx %s) but no Secrets.SecretStored event for this account was "+
			"finalized in time; it may still land, so check the chain before resubmitting",
		txHash)
}

func (c *ChainClient) secretExistsAt(at types.Hash, id SecretID) (bool, error) {
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
