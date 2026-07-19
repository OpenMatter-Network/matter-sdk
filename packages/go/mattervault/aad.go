package mattervault

// Aad is a versioned associated-data tag a secret is sealed under. Use the
// constants, never a raw string, so a typo is a compile error rather than a
// silent decrypt failure. Values are a wire contract; treat them as append-only.
type Aad string

const (
	AadEnvV1                Aad = "matter-deployment/env/v1"
	AadTlsV1                Aad = "matter-deployment/tls/v1"
	AadStorageCredsV1       Aad = "matter-volume/storage-creds/v1"
	AadVolumeDekV1          Aad = "matter-volume/dek/v1"
	AadDatasetSourceCredsV1 Aad = "matter-dataset/source-creds/v1"
)

// AadBytes returns the canonical bytes for an AAD tag.
func AadBytes(a Aad) []byte { return []byte(a) }
