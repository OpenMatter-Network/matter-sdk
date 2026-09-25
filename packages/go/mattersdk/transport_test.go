package mattersdk

// The committee wire format is a cross-repo contract: these pin the exact paths,
// method, content type and JSON field names.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPTransportHealth(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active","epoch":7,"crypto_protocol_version":2}`))
	}))
	defer server.Close()

	h, err := NewHTTPTransport().Health(server.URL)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if gotPath != "/health" {
		t.Errorf("path = %q, want /health", gotPath)
	}
	if h.Status != "active" || h.Epoch != 7 || h.CryptoProtocolVersion != 2 {
		t.Errorf("decoded %+v", h)
	}
}

func TestHTTPTransportTrimsTrailingSlashes(t *testing.T) {
	// A double slash would 404 on a strict router.
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"status":"active","epoch":0}`))
	}))
	defer server.Close()

	if _, err := NewHTTPTransport().Health(server.URL + "///"); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if gotPath != "/health" {
		t.Errorf("path = %q, want /health", gotPath)
	}
}

func TestHTTPTransportPartialDecrypt(t *testing.T) {
	var (
		gotPath        string
		gotMethod      string
		gotContentType string
		gotBody        map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotContentType = r.Header.Get("content-type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"node_index":3,"partial":"0xaa","proof":"0xbb","served_epoch":7}`))
	}))
	defer server.Close()

	req := PartialDecryptRequest{
		SecretID:      "0x00",
		Subset:        []uint64{1, 3, 5},
		LagrangeCoeff: "0xcc",
		Requester:     "0xdd",
		BlockHash:     "0xee",
		Signature:     "0xff",
		Auth:          "substrate",
	}
	resp, err := NewHTTPTransport().PartialDecrypt(server.URL, req)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}

	if gotPath != "/partial-decrypt" || gotMethod != http.MethodPost {
		t.Errorf("%s %s, want POST /partial-decrypt", gotMethod, gotPath)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Errorf("content-type = %q", gotContentType)
	}
	for _, field := range []string{"secret_id", "subset", "lagrange_coeff", "requester", "block_hash", "signature", "auth"} {
		if _, ok := gotBody[field]; !ok {
			t.Errorf("request body is missing %q", field)
		}
	}
	if resp.NodeIndex != 3 || resp.Partial != "0xaa" || resp.Proof != "0xbb" || resp.ServedEpoch != 7 {
		t.Errorf("decoded %+v", resp)
	}
}

func TestHTTPTransportNon200IsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("not authorized for this secret"))
	}))
	defer server.Close()

	transport := NewHTTPTransport()

	if _, err := transport.Health(server.URL); err == nil {
		t.Error("health: expected an error on 403")
	}

	_, err := transport.PartialDecrypt(server.URL, PartialDecryptRequest{})
	if err == nil {
		t.Fatal("partial-decrypt: expected an error on 403")
	}
	// The body carries the node's reason, e.g. "not finalized" or "not authorized".
	if !strings.Contains(err.Error(), "not authorized for this secret") {
		t.Errorf("error does not carry the node's response body: %v", err)
	}
}

func TestHTTPTransportUnreachableEndpointIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening now

	if _, err := NewHTTPTransport().Health(url); err == nil {
		t.Error("expected a connection error")
	}
}

func TestHTTPTransportRefusesABodyOverTheCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"active","epoch":0,"padding":"` + strings.Repeat("x", 64) + `"}`))
	}))
	defer server.Close()

	tr := NewHTTPTransport()
	tr.MaxResponseBytes = 32
	if _, err := tr.Health(server.URL); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("want a size-cap error, got %v", err)
	}
}

func TestHTTPTransportDefaultsToTheCoreCap(t *testing.T) {
	if got, want := NewHTTPTransport().MaxResponseBytes, MaxCommitteeResponseBytes(); got != want || want == 0 {
		t.Fatalf("MaxResponseBytes = %d, want the core cap %d", got, want)
	}
	// A zero-value transport must not mean "unbounded".
	if got := (&HTTPTransport{}).maxResponseBytes(); got != MaxCommitteeResponseBytes() {
		t.Fatalf("zero-value cap = %d, want the core cap", got)
	}
}
