package mattersdk

// Live check that GSRPC's event retriever decodes this runtime: it builds a type
// registry from the whole metadata, which no fake can prove. Needs the network:
//
//	MATTER_LIVE=yes go test -run Live -v ./...

import (
	"os"
	"testing"
)

const liveEnv = "MATTER_LIVE"

func liveClient(t *testing.T) *ChainClient {
	t.Helper()
	if os.Getenv(liveEnv) != "yes" {
		t.Skipf("set %s=yes to run against the live testnet", liveEnv)
	}
	url := os.Getenv("MATTER_RPC_URL")
	if url == "" {
		url = "wss://node2.testnet.openmatter.network"
	}
	client, err := NewChainClient(url)
	if err != nil {
		t.Fatalf("connect to %s: %v", url, err)
	}
	return client
}

func TestLiveEventRetrieverDecodesAFinalizedBlock(t *testing.T) {
	client := liveClient(t)

	head, err := client.api.RPC.Chain.GetFinalizedHead()
	if err != nil {
		t.Fatalf("finalized head: %v", err)
	}

	events, err := client.EventsAt(head)
	if err != nil {
		t.Fatalf("EventsAt(%s): %v — the retriever may need registry.FieldOverrides "+
			"for this runtime's types", head.Hex(), err)
	}

	// Every block has the timestamp extrinsic's success event; none means a silent
	// decode failure.
	if len(events) == 0 {
		t.Fatal("decoded zero events from a finalized block")
	}

	sawSystem := false
	for _, e := range events {
		if e.Pallet == "" {
			t.Errorf("event %q has no pallet: the Pallet.Name split failed", e.Name)
		}
		if e.Pallet == "System" {
			sawSystem = true
		}
		t.Logf("  %s (%d fields)", e, len(e.Fields))
	}
	if !sawSystem {
		t.Error("no System events in a finalized block; the decode is likely wrong")
	}
}

func TestLiveSecretStoredEventYieldsASecretID(t *testing.T) {
	// Skips, rather than fails, if no secret was stored in the scanned window.
	client := liveClient(t)

	head, err := client.api.RPC.Chain.GetFinalizedHead()
	if err != nil {
		t.Fatalf("finalized head: %v", err)
	}
	header, err := client.api.RPC.Chain.GetHeader(head)
	if err != nil {
		t.Fatalf("header: %v", err)
	}

	const scanBlocks = 200
	for n := uint64(header.Number); n > 0 && n > uint64(header.Number)-scanBlocks; n-- {
		hash, err := client.api.RPC.Chain.GetBlockHash(n)
		if err != nil {
			continue
		}
		event, found, err := client.FindEvent(hash, "Secrets", "SecretStored")
		if err != nil || !found {
			continue
		}

		id, err := SecretIDFromEvent(event)
		if err != nil {
			t.Fatalf("SecretIDFromEvent(%s): %v", event, err)
		}
		t.Logf("block %d: %s -> secret id %s", n, event, id)

		// Resolving on chain proves the right field was read.
		if _, err := client.SecretEpoch(id); err != nil {
			t.Errorf("secret %s from the event does not resolve on chain: %v", id, err)
		}
		return
	}
	t.Skipf("no Secrets.SecretStored event in the last %d finalized blocks", scanBlocks)
}
