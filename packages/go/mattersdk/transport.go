package mattersdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Health is a committee node's /health response.
type Health struct {
	Status                string `json:"status"`
	Epoch                 uint32 `json:"epoch"`
	CryptoProtocolVersion uint16 `json:"crypto_protocol_version"`
}

// PartialDecryptRequest is the /partial-decrypt request body (the on-chain wire type).
type PartialDecryptRequest struct {
	SecretID      string   `json:"secret_id"`
	Subset        []uint64 `json:"subset"`
	LagrangeCoeff string   `json:"lagrange_coeff"`
	Requester     string   `json:"requester"`
	BlockHash     string   `json:"block_hash"`
	Signature     string   `json:"signature"`
	Auth          string   `json:"auth"`
	// The Ethereum-auth fields, omitted on the Substrate path.
	EthAddress   *string `json:"eth_address,omitempty"`
	ValidUntil   *uint64 `json:"valid_until,omitempty"`
	EthSignature *string `json:"eth_signature,omitempty"`
}

// PartialDecryptResponse is the /partial-decrypt response body.
type PartialDecryptResponse struct {
	NodeIndex   uint64 `json:"node_index"`
	Partial     string `json:"partial"`
	Proof       string `json:"proof"`
	ServedEpoch uint32 `json:"served_epoch"`
}

// Transport is how the SDK reaches committee nodes. Swap in a fake for tests.
type Transport interface {
	Health(endpoint string) (Health, error)
	PartialDecrypt(endpoint string, req PartialDecryptRequest) (PartialDecryptResponse, error)
}

// HTTPTransport is a net/http-based Transport.
type HTTPTransport struct {
	Client *http.Client
	// MaxResponseBytes caps each response body against a hostile node. Zero
	// means MaxCommitteeResponseBytes, never unbounded.
	MaxResponseBytes int64
}

// NewHTTPTransport returns a transport with a default 20s timeout and the core's
// response-size cap.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{
		Client:           &http.Client{Timeout: 20 * time.Second},
		MaxResponseBytes: MaxCommitteeResponseBytes(),
	}
}

func (t *HTTPTransport) maxResponseBytes() int64 {
	if t.MaxResponseBytes > 0 {
		return t.MaxResponseBytes
	}
	return MaxCommitteeResponseBytes()
}

// decodeCapped JSON-decodes body into v, refusing a body over the cap.
func (t *HTTPTransport) decodeCapped(body io.Reader, endpoint string, v any) error {
	limit := t.maxResponseBytes()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("response from %s exceeded %d bytes", endpoint, limit)
	}
	return json.Unmarshal(data, v)
}

func (t *HTTPTransport) Health(endpoint string) (Health, error) {
	var h Health
	resp, err := t.Client.Get(strings.TrimRight(endpoint, "/") + "/health")
	if err != nil {
		return h, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return h, fmt.Errorf("health %d from %s", resp.StatusCode, endpoint)
	}
	return h, t.decodeCapped(resp.Body, endpoint, &h)
}

func (t *HTTPTransport) PartialDecrypt(endpoint string, req PartialDecryptRequest) (PartialDecryptResponse, error) {
	var pr PartialDecryptResponse
	body, err := json.Marshal(req)
	if err != nil {
		return pr, err
	}
	resp, err := t.Client.Post(strings.TrimRight(endpoint, "/")+"/partial-decrypt", "application/json", bytes.NewReader(body))
	if err != nil {
		return pr, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return pr, fmt.Errorf("partial-decrypt %d from %s: %s", resp.StatusCode, endpoint, strings.TrimSpace(string(msg)))
	}
	return pr, t.decodeCapped(resp.Body, endpoint, &pr)
}
