package mattersdk

// Every catalogue read against a live chain, read-only: no key, no submission.
// Strict decoders fail when a forkless upgrade changes a layout, and this is where
// that shows first. Needs the network:
//
//	MATTER_LIVE=yes go test -run LiveReads -v ./...
//
// MATTER_AT_BLOCK pins the block; MATTER_LIVE_READS_OUT writes the results, for
// scripts/compare-live-reads.sh to hold the four bindings to the same bytes.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type liveRead struct {
	Facade string         `json:"facade"`
	Method string         `json:"method"`
	Args   map[string]any `json:"args"`
	// ResultJSON is the canonical text itself: the comparison is of bytes, not
	// parsed values.
	ResultJSON string `json:"result_json,omitempty"`
}

func TestLiveReadsDecodeAgainstTheLiveRuntime(t *testing.T) {
	if os.Getenv(liveEnv) != "yes" {
		t.Skipf("set %s=yes to run against the live testnet", liveEnv)
	}
	fixture := loadReadFixture(t)
	var live struct {
		Reads []liveRead `json:"reads"`
	}
	load(t, "live_reads.json", &live)

	pinned := map[string]readRow{}
	for _, row := range fixture.Reads {
		pinned[row.Facade+"."+row.Method] = row
	}
	exercised := map[string]bool{}
	for _, row := range live.Reads {
		name := row.Facade + "." + row.Method
		if _, ok := pinned[name]; !ok {
			t.Fatalf("live_reads.json names %s, which the catalogue does not pin", name)
		}
		exercised[name] = true
	}
	if len(exercised) != len(pinned) {
		t.Fatalf("live_reads.json exercises %d reads, the catalogue pins %d", len(exercised), len(pinned))
	}

	client, err := Connect(Config{RPCURL: os.Getenv("MATTER_RPC_URL")})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	at := os.Getenv("MATTER_AT_BLOCK")
	if at == "" {
		head, err := client.Chain().FinalizedHead()
		if err != nil {
			t.Fatalf("finalized head: %v", err)
		}
		at = toHex(head[:])
	}
	if raw, err := hex.DecodeString(strings.TrimPrefix(at, hexPrefix)); err != nil || len(raw) != blockHashBytes {
		t.Fatalf("MATTER_AT_BLOCK is not a 32-byte block hash: %q", at)
	}

	reads := make([]liveRead, len(live.Reads))
	for i, row := range live.Reads {
		testCase := readCase{Name: "live", Args: row.Args, At: strings.TrimPrefix(at, hexPrefix)}
		catalogued := pinned[row.Facade+"."+row.Method]
		result, err := callRead(t, client, fixture, catalogued, testCase, catalogued.Pinnable)
		if err != nil {
			t.Fatalf("%s.%s(%v) at %s: %v", row.Facade, row.Method, row.Args, at, err)
		}
		canonical, err := CanonicalJSON(result)
		if err != nil {
			t.Fatal(err)
		}
		reads[i] = liveRead{row.Facade, row.Method, row.Args, canonical}
		t.Logf("%s.%s(%v) = %s", row.Facade, row.Method, row.Args, canonical)
	}

	if out := os.Getenv("MATTER_LIVE_READS_OUT"); out != "" {
		raw, err := json.MarshalIndent(map[string]any{"at": at, "reads": reads}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
	}
}
