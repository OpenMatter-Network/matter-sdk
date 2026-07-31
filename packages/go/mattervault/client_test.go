package mattervault

// MatterClient behaviour that does not need a chain: the network guards, the amount
// arithmetic, and the read-only contract. These are the parts that must never
// regress, because getting them wrong spends real money.

import (
	"math/big"
	"os"
	"strings"
	"testing"
)

func testProperties(symbol, genesis string, declared, effective uint8) ChainProperties {
	name := "MatterChain Testnet"
	if symbol == MainnetTokenSymbol {
		name = "MatterChain"
	}
	return ChainProperties{
		GenesisHash:            genesis,
		ChainName:              name,
		SpecVersion:            308,
		TokenSymbol:            symbol,
		SS58Prefix:             42,
		TokenDecimalsDeclared:  declared,
		TokenDecimalsEffective: effective,
		ExistentialDeposit:     OneToken(effective - 3),
	}
}

// --- amounts ---------------------------------------------------------------

func TestAmountsRoundTripLosslessly(t *testing.T) {
	// A UI that displays a balance and submits it back must not change it.
	for _, decimals := range []uint8{0, 3, 12, 18} {
		values := []*big.Int{
			big.NewInt(0), big.NewInt(1), big.NewInt(999),
			OneToken(decimals),
			new(big.Int).Lsh(big.NewInt(1), 70), // beyond uint64
		}
		for _, want := range values {
			text := FormatAmount(want, decimals)
			got, err := ParseAmount(text, decimals)
			if err != nil {
				t.Fatalf("decimals=%d text=%q: %v", decimals, text, err)
			}
			if got.Cmp(want) != 0 {
				t.Errorf("decimals=%d: %s -> %q -> %s", decimals, want, text, got)
			}
		}
	}
}

func TestAmountsRejectExcessPrecisionRatherThanTruncating(t *testing.T) {
	if got, err := ParseAmount("0.001", 3); err != nil || got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("0.001 at 3 decimals = %v, %v", got, err)
	}
	if _, err := ParseAmount("0.0001", 3); err == nil {
		t.Error("an over-precise amount must be rejected, not rounded")
	}
}

func TestAmountsRejectMalformedInput(t *testing.T) {
	for _, bad := range []string{"", "   ", "-1", "-0.5", "abc", "1.2.3", "1,5", "1.", ".5", "1e9"} {
		if _, err := ParseAmount(bad, 12); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTheDecimalsDiscrepancyIsAFactorOfAMillion(t *testing.T) {
	// matter-node changed UNIT from 10^12 to 10^18 with no storage migration, so the
	// same plancks value means amounts a million-fold apart.
	plancks := OneToken(15)
	if got := FormatAmount(plancks, 18); got != "0.001" {
		t.Errorf("at 18 decimals = %q, want 0.001", got)
	}
	if got := FormatAmount(plancks, 12); got != "1000" {
		t.Errorf("at 12 decimals = %q, want 1000", got)
	}
}

func TestDecimalsDeriveFromTheExistentialDeposit(t *testing.T) {
	for _, tc := range []struct {
		ed    *big.Int
		want  uint8
		valid bool
	}{
		{OneToken(15), 18, true},
		{OneToken(9), 12, true},
		{big.NewInt(1), 3, true},
		// Not a clean power of ten: the ED policy changed, so fall back rather than
		// reporting a confidently wrong exponent.
		{big.NewInt(1500), 0, false},
		{big.NewInt(0), 0, false},
		{nil, 0, false},
	} {
		got, ok := decimalsFromExistentialDeposit(tc.ed)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Errorf("ed=%v -> (%d, %v), want (%d, %v)", tc.ed, got, ok, tc.want, tc.valid)
		}
	}
}

func TestClientAmountHelpersUseTheEffectiveDecimals(t *testing.T) {
	// Not the declared ones: that is the whole point of tracking both.
	client := &MatterClient{properties: testProperties("MTR-Test", TestnetGenesis, 18, 12)}
	if got := client.OneToken(); got.Cmp(OneToken(12)) != 0 {
		t.Errorf("OneToken = %s, want 10^12", got)
	}
	parsed, err := client.ParseAmount("1")
	if err != nil || parsed.Cmp(OneToken(12)) != 0 {
		t.Errorf("ParseAmount(\"1\") = %v, %v", parsed, err)
	}
	if got := client.FormatAmount(OneToken(12)); got != "1" {
		t.Errorf("FormatAmount = %q, want \"1\"", got)
	}
}

// --- the network guards ----------------------------------------------------

func TestThePinnedTestnetGenesisWinsOverTheTokenSymbol(t *testing.T) {
	// Even with mainnet's symbol, a matching genesis hash means testnet.
	props := testProperties(MainnetTokenSymbol, TestnetGenesis, 18, 18)
	isMainnet, via := props.IsMainnet()
	if isMainnet || via != "genesis-hash" {
		t.Errorf("IsMainnet = (%v, %q), want (false, genesis-hash)", isMainnet, via)
	}
}

func TestAnUnknownChainFallsBackToTheTokenSymbol(t *testing.T) {
	unknown := "0x" + strings.Repeat("ab", 32)

	isMainnet, via := testProperties("MTR", unknown, 18, 18).IsMainnet()
	if !isMainnet || via != "token-symbol" {
		t.Errorf("MTR -> (%v, %q), want (true, token-symbol)", isMainnet, via)
	}
	if isMainnet, _ := testProperties("MTR-Test", unknown, 18, 18).IsMainnet(); isMainnet {
		t.Error("MTR-Test must not read as mainnet")
	}
}

func TestATestnetConfigPointedAtMainnetIsRejected(t *testing.T) {
	// A typo'd RPC URL must fail before it costs anything.
	client := &MatterClient{
		properties: testProperties("MTR", "0x"+strings.Repeat("ab", 32), 18, 18),
		signer:     &ApiKey{},
		config:     Config{Network: NetworkTestnet},
	}
	err := client.enforceNetworkGuards()
	if err == nil || !strings.Contains(err.Error(), "expected the testnet network") {
		t.Errorf("guard did not fire: %v", err)
	}
}

func TestASigningClientNeedsConfirmationForMainnet(t *testing.T) {
	mainnet := testProperties("MTR", "0x"+strings.Repeat("ab", 32), 18, 18)

	unconfirmed := &MatterClient{
		properties: mainnet,
		signer:     &ApiKey{},
		config:     Config{Network: NetworkMainnet},
	}
	if err := unconfirmed.enforceNetworkGuards(); err == nil {
		t.Fatal("a signing mainnet client must require confirmation")
	} else if !strings.Contains(err.Error(), "without explicit confirmation") {
		t.Errorf("unexpected message: %v", err)
	}

	confirmed := &MatterClient{
		properties: mainnet,
		signer:     &ApiKey{},
		config:     Config{Network: NetworkMainnet, ConfirmMainnet: true},
	}
	if err := confirmed.enforceNetworkGuards(); err != nil {
		t.Errorf("explicit confirmation was rejected: %v", err)
	}

	// The environment variable is the other accepted acknowledgement.
	t.Setenv(confirmEnv, confirmValue)
	viaEnv := &MatterClient{
		properties: mainnet,
		signer:     &ApiKey{},
		config:     Config{Network: NetworkMainnet},
	}
	if err := viaEnv.enforceNetworkGuards(); err != nil {
		t.Errorf("%s=%s was rejected: %v", confirmEnv, confirmValue, err)
	}
}

func TestAReadOnlyClientMayReachMainnetWithoutConfirmation(t *testing.T) {
	// Reading cannot spend anything, so the guard does not apply.
	os.Unsetenv(confirmEnv)
	client := &MatterClient{
		properties: testProperties("MTR", "0x"+strings.Repeat("ab", 32), 18, 18),
		config:     Config{Network: NetworkMainnet},
	}
	if err := client.enforceNetworkGuards(); err != nil {
		t.Errorf("a read-only mainnet client was rejected: %v", err)
	}
}

// --- configuration and the read-only contract ------------------------------

func TestConfigResolvesTheRightEndpoint(t *testing.T) {
	if url, err := (Config{}).resolveURL(); err != nil || url != TestnetRPC {
		t.Errorf("empty config -> %q, %v; want the testnet default", url, err)
	}
	if url, _ := (Config{Network: NetworkMainnet}).resolveURL(); url != MainnetRPC {
		t.Errorf("mainnet -> %q", url)
	}
	if _, err := (Config{Network: NetworkCustom}).resolveURL(); err == nil {
		t.Error("a custom network without an explicit URL must fail")
	}
	if url, _ := (Config{Network: NetworkCustom, RPCURL: "ws://x"}).resolveURL(); url != "ws://x" {
		t.Errorf("explicit URL -> %q", url)
	}
}

func TestAReadOnlyClientRefusesToSubmit(t *testing.T) {
	client := &MatterClient{properties: testProperties("MTR-Test", TestnetGenesis, 18, 18)}
	if client.AccountID() != nil || client.AccountIDHex() != "" {
		t.Error("a read-only client must report no identity")
	}
	if _, err := client.Signer(); err == nil {
		t.Error("a read-only client must not produce a committee signer")
	}
}

func TestConnectRejectsANilKeyOrSigner(t *testing.T) {
	// Passing nil should say "use Connect" rather than building a client that looks
	// signing-capable and fails later.
	if _, err := ConnectWithApiKey(Config{}, nil); err == nil {
		t.Error("ConnectWithApiKey(nil) must fail")
	}
	if _, err := ConnectWithSigner(Config{}, nil); err == nil {
		t.Error("ConnectWithSigner(nil) must fail")
	}
}
