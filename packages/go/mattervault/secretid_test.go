package mattervault

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestSecretIDRoundTripsThroughEveryForm(t *testing.T) {
	// The fixture id, plus a value that needs the high half.
	for _, decimal := range []string{"0", "1", "81985529216486895", "18446744073709551616", "340282366920938463463374607431768211455"} {
		id, err := ParseSecretID(decimal)
		if err != nil {
			t.Fatalf("ParseSecretID(%q): %v", decimal, err)
		}
		if id.String() != decimal {
			t.Errorf("String() = %q, want %q", id.String(), decimal)
		}
		if got, err := ParseSecretID(id.Hex()); err != nil || got != id {
			t.Errorf("hex round trip failed for %q: %v", decimal, err)
		}
		if got := SecretIDFromBytes(id.Bytes()); got != id {
			t.Errorf("byte round trip failed for %q", decimal)
		}
	}
}

func TestSecretIDBigEndianMatchesSigningPayloadForm(t *testing.T) {
	// The signing payload is a cross-language contract: 16 big-endian bytes.
	id := NewSecretID(0x0123456789abcdef)
	b := id.Bytes()
	if got := hex.EncodeToString(b[:]); got != "00000000000000000123456789abcdef" {
		t.Errorf("Bytes() = %s", got)
	}
	// The runtime-API argument form is the same value little-endian.
	le := id.LEBytes()
	if got := hex.EncodeToString(le[:]); got != "efcdab89674523010000000000000000" {
		t.Errorf("LEBytes() = %s", got)
	}
}

func TestSecretIDCarriesValuesAboveUint64(t *testing.T) {
	// The whole point: a value the old uint64 representation would have lost.
	big65 := new(big.Int).Lsh(big.NewInt(1), 65) // 2^65
	id, err := ParseSecretID(big65.String())
	if err != nil {
		t.Fatalf("ParseSecretID: %v", err)
	}
	if id.IsUint64() {
		t.Fatal("2^65 must not report as fitting in a uint64")
	}
	if id.String() != big65.String() {
		t.Errorf("value was truncated: %s", id.String())
	}

	defer func() {
		if recover() == nil {
			t.Error("Uint64() must panic rather than silently truncate")
		}
	}()
	_ = id.Uint64()
}

func TestSecretIDRejectsInvalidInput(t *testing.T) {
	for _, bad := range []string{"", "   ", "-1", "nope", "0xzz", strings.Repeat("9", 40)} {
		if _, err := ParseSecretID(bad); err == nil {
			t.Errorf("accepted invalid secret id %q", bad)
		}
	}
}

func TestSecretIDSurvivesJSON(t *testing.T) {
	// Decimal text, not a number: JSON numbers are float64 and would silently
	// lose precision above 2^53.
	id, err := ParseSecretID("81985529216486895")
	if err != nil {
		t.Fatalf("ParseSecretID: %v", err)
	}
	blob, err := json.Marshal(struct {
		ID SecretID `json:"id"`
	}{id})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"81985529216486895"`) {
		t.Errorf("marshalled as %s, want a decimal string", blob)
	}

	var back struct {
		ID SecretID `json:"id"`
	}
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.ID != id {
		t.Error("JSON round trip changed the id")
	}
}

func TestSecretIDZeroValueIsUsable(t *testing.T) {
	var id SecretID
	if id.String() != "0" || !id.IsUint64() || id.Uint64() != 0 {
		t.Error("the zero value must be a valid id of 0")
	}
}
