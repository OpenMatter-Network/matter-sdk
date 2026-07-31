package mattervault

// GrantTarget encoding. The chain's GrantTarget<AccountId> is a SCALE enum, and
// getting the variant index or payload wrong grants access to the wrong principal
// — or produces call data the runtime cannot decode at all, which is what the
// other bindings were doing.

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGrantTargetVariantIndicesMatchTheRuntimeEnum(t *testing.T) {
	// `pub enum GrantTarget<AccountId> { User(AccountId), Deployment(u128) }` —
	// declaration order is the SCALE index.
	if GrantUser != 0 {
		t.Errorf("GrantUser = %d, want 0", GrantUser)
	}
	if GrantDeployment != 1 {
		t.Errorf("GrantDeployment = %d, want 1", GrantDeployment)
	}
}

func TestUserTargetEncodesVariantThenAccount(t *testing.T) {
	account := bytes.Repeat([]byte{0xab}, accountIDBytes)
	target, err := UserTarget(account)
	if err != nil {
		t.Fatalf("UserTarget: %v", err)
	}

	encoded, err := target.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != 1+accountIDBytes {
		t.Fatalf("encoded %d bytes, want %d", len(encoded), 1+accountIDBytes)
	}
	if encoded[0] != byte(GrantUser) {
		t.Errorf("variant byte = %d, want %d", encoded[0], GrantUser)
	}
	if !bytes.Equal(encoded[1:], account) {
		t.Error("account was not written verbatim after the variant byte")
	}
}

func TestDeploymentTargetEncodesVariantThenLittleEndianU128(t *testing.T) {
	target := DeploymentTarget(NewSecretID(0x0123456789abcdef))

	encoded, err := target.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != 17 {
		t.Fatalf("encoded %d bytes, want 17 (variant + u128)", len(encoded))
	}
	if encoded[0] != byte(GrantDeployment) {
		t.Errorf("variant byte = %d, want %d", encoded[0], GrantDeployment)
	}
	// SCALE encodes a u128 little-endian.
	if got := hex.EncodeToString(encoded[1:]); got != "efcdab89674523010000000000000000" {
		t.Errorf("deployment id encoded as %s", got)
	}
}

func TestUserTargetRejectsWrongSizedAccounts(t *testing.T) {
	for _, size := range []int{0, 31, 33, 64} {
		if _, err := UserTarget(make([]byte, size)); err == nil {
			t.Errorf("accepted a %d-byte account", size)
		}
	}
}

func TestGrantTargetRefusesToEncodeAnUnknownKind(t *testing.T) {
	// A zero-value-adjacent struct with a bogus kind must not silently encode as
	// User, which would grant to whatever bytes happened to be in Account.
	bogus := GrantTarget{Kind: GrantTargetKind(9)}
	if _, err := bogus.encode(); err == nil {
		t.Error("an unknown grant target kind must not encode")
	}
}

func TestGrantTargetStringIsReadable(t *testing.T) {
	// These end up in errors; an opaque struct dump makes a misgrant hard to spot.
	user, err := UserTarget(bytes.Repeat([]byte{0x07}, accountIDBytes))
	if err != nil {
		t.Fatalf("UserTarget: %v", err)
	}
	if !strings.HasPrefix(user.String(), "User(0x0707") {
		t.Errorf("User target renders as %q", user.String())
	}
	if got := DeploymentTarget(NewSecretID(42)).String(); got != "Deployment(42)" {
		t.Errorf("Deployment target renders as %q", got)
	}
}
