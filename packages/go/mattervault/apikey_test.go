package mattervault

// API-key ingestion conformance: replays testvectors/api_keys.json so this
// binding agrees with every other on what parses, what is rejected, and which
// account each key derives.
//
// The redaction cases are Go-specific: fmt verbs and encoding/json are how a
// credential reaches a log line in this runtime.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	vectorMnemonic = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
	vectorSeedHex  = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"
	// The secret body, used to assert it never appears in any rendering.
	vectorSeedBody = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"
)

type apiKeyVectors struct {
	Valid []struct {
		Name         string `json:"name"`
		Key          string `json:"key"`
		AccountIDHex string `json:"account_id_hex"`
	} `json:"valid"`
	Invalid []struct {
		Name  string `json:"name"`
		Key   string `json:"key"`
		Error string `json:"error"`
	} `json:"invalid"`
}

func TestApiKeyConformance(t *testing.T) {
	var doc apiKeyVectors
	load(t, "api_keys.json", &doc)

	if len(doc.Valid) == 0 || len(doc.Invalid) == 0 {
		t.Fatal("api_keys.json has no cases; regenerate it")
	}

	for _, c := range doc.Valid {
		t.Run("valid/"+c.Name, func(t *testing.T) {
			key, err := NewApiKey(c.Key)
			if err != nil {
				t.Fatalf("NewApiKey: %v", err)
			}
			defer key.Close()

			if got := key.AccountIDHex(); got != "0x"+c.AccountIDHex {
				t.Errorf("account = %s, want 0x%s", got, c.AccountIDHex)
			}
			if key.Scheme() != "sr25519" {
				t.Errorf("scheme = %q", key.Scheme())
			}
			if len(key.AccountID()) != accountIDBytes {
				t.Errorf("account id is %d bytes", len(key.AccountID()))
			}
		})
	}

	for _, c := range doc.Invalid {
		t.Run("invalid/"+c.Name, func(t *testing.T) {
			key, err := NewApiKey(c.Key)
			if err == nil {
				key.Close()
				t.Fatalf("%q was accepted", c.Name)
			}
		})
	}
}

func TestApiKeyAppliesJunctions(t *testing.T) {
	// The failure this guards: dropping the derivation path and silently
	// returning the root account.
	root, err := NewApiKey(vectorSeedHex)
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer root.Close()

	hard, err := NewApiKey(vectorSeedHex + "//hard")
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer hard.Close()

	if hard.AccountIDHex() == root.AccountIDHex() {
		t.Fatal("//hard derived the root account; the junction was dropped")
	}

	// The mnemonic form of the same secret must land on the same account.
	fromMnemonic, err := NewApiKey(vectorMnemonic + "//hard")
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer fromMnemonic.Close()

	if fromMnemonic.AccountIDHex() != hard.AccountIDHex() {
		t.Error("hex and mnemonic forms of the same secret derived different accounts")
	}
}

func TestApiKeyRedactsThroughEveryRenderingPath(t *testing.T) {
	key, err := NewApiKey(vectorSeedHex)
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer key.Close()

	type wrapper struct {
		Key  *ApiKey
		Note string
	}

	renderings := []string{
		key.String(),
		fmt.Sprintf("%v", key),
		fmt.Sprintf("%s", key),
		fmt.Sprintf("%+v", key),
		fmt.Sprintf("%v", wrapper{key, "n"}),
		fmt.Sprintf("%+v", wrapper{key, "n"}),
		fmt.Sprintf("%v", []*ApiKey{key}),
		fmt.Sprintf("%v", map[string]*ApiKey{"k": key}),
	}
	for i, rendered := range renderings {
		if strings.Contains(strings.ToLower(rendered), vectorSeedBody) {
			t.Errorf("rendering %d leaked the key: %s", i, rendered)
		}
		if !strings.Contains(rendered, "<redacted>") {
			t.Errorf("rendering %d is not redacted: %s", i, rendered)
		}
	}
}

func TestApiKeyRefusesToSerialize(t *testing.T) {
	key, err := NewApiKey(vectorMnemonic)
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer key.Close()

	if _, err := json.Marshal(key); err == nil {
		t.Error("json.Marshal of an ApiKey must fail rather than emit anything")
	}
	// And when nested, so it cannot slip through inside a config struct.
	if _, err := json.Marshal(struct {
		Key *ApiKey `json:"key"`
	}{key}); err == nil {
		t.Error("a nested ApiKey must also refuse to serialize")
	}
}

func TestApiKeySignsAsTheClaimedAccount(t *testing.T) {
	key, err := NewApiKey(vectorSeedHex)
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	defer key.Close()

	sig, err := key.Sign([]byte("canonical payload bytes"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != sr25519SignatureBytes {
		t.Fatalf("signature is %d bytes, want %d", len(sig), sr25519SignatureBytes)
	}

	// The committee adapter must frame that signature and advertise the same
	// account, so one key serves both the chain and the committee.
	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	auth, err := signer.Authorize(NewSecretID(1), []uint64{1}, 1, [32]byte{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Requester != key.AccountIDHex() {
		t.Errorf("requester = %s, want %s", auth.Requester, key.AccountIDHex())
	}
}

func TestApiKeyCloseIsIdempotentAndDisablesSigning(t *testing.T) {
	key, err := NewApiKey(vectorSeedHex)
	if err != nil {
		t.Fatalf("NewApiKey: %v", err)
	}
	key.Close()
	key.Close() // must not double-free

	if _, err := key.Sign([]byte("x")); err == nil {
		t.Error("signing with a closed key must fail")
	}
}
