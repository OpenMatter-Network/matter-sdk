# Security Policy

MatterSDK signs transactions and recovers secrets in the process that embeds it. This page
covers how to report a problem, what the SDK protects against, how it handles secret
material, and where your keys should live.

## Reporting a vulnerability

Email **security@openmatter.network** with details and, if you can, a reproduction. Do
**not** open a public issue. We acknowledge within 3 business days.

## Threat model

What MatterSDK guarantees:

- **A stolen ciphertext is useless.** An on-chain `EncryptedSecret` reveals nothing
  without a `t`-of-`n` committee quorum, even though anyone can read the chain.
- **No single committee node can decrypt.** Each node holds one Shamir share of the
  committee key. Its partial decryption is useless on its own, and the full key is never
  assembled anywhere.
- **Data sealed today stays sealed.** The encryption is lattice-based (RLWE/BGV), the
  family NIST standardised for post-quantum cryptography, so ciphertext harvested now
  cannot be opened later by a quantum computer.
- **A captured `/partial-decrypt` request cannot be replayed.** Its signature binds
  `(secret_id, subset, block_hash, recipient_node)`, plus `valid_until` on the Ethereum
  path. Each node checks it against its own index. A recorded request cannot be aimed at
  another secret, replayed after its freshness window, or forwarded by one quorum member
  to its peers to assemble a quorum.
- **Only authorised accounts can request a decryption.** Each node checks the signer
  against the secret's on-chain grants before it serves a partial.
- **A scoped API key cannot exceed its grant.** The runtime enforces the member's scopes
  on every call a delegated key makes. The SDK's local scope check only makes refusals
  arrive earlier and read more clearly ([keys and scopes](docs/keys-and-scopes.md)).

What it does **not** protect against, by design:

- **A colluding quorum.** `t` or more committee nodes acting together can recover the
  secrets they are asked to decrypt. Choose `t`, `n` and the node operators accordingly.
- **Plaintext after it is returned to you.** The SDK wipes its own copies and never logs
  plaintext. It hands you a buffer you can wipe, and protecting that buffer is your job.
- **A compromised signer.** A stolen signing key can do everything its account, or its
  scopes, allow. That includes requesting every secret the account is granted. Keep
  production keys in an HSM or KMS ([secure signing](docs/secure-signing.md)).

## How the SDK handles secrets

- **Recovered plaintext is zeroized.** Rust returns a `Plaintext` that wipes itself on
  drop and redacts `Debug`. Go, Python and TypeScript wipe the core's copy before it is
  freed. They return a mutable buffer with a `wipe` helper (`mattersdk.Wipe`,
  `matter_sdk.wipe`, `wipe`) for the host language's copy.
- **Nothing secret is logged.** Key material and plaintext never appear in a log line,
  error message, panic or debug representation. Key-parsing errors never echo their
  input.
- **Inputs are validated at the boundary.** Wrong-length ids, oversized envelopes and
  malformed hex are rejected with typed errors and never coerced. Everything decoded
  from the chain or a committee node is size-bounded and must decode exactly, with no
  trailing bytes. The core derives every Lagrange coefficient itself and rejects a
  repeated or zero node index.
- **The C ABI fails closed.** No panic unwinds across it (`MSDK_ERR_INTERNAL`).
  Out-parameters are cleared on every error path, `msdk_free` wipes buffers before
  freeing them, and a null pointer with a non-zero length is an error.
- **No single node can deny or monopolise a decryption.** Each decrypt picks its quorum
  at random from the healthy nodes. A node is dropped when it fails, speaks another
  protocol version or serves a different epoch, and the error names every dropped node.
  Every committee request has a deadline and a response-size cap.

## Key-holding paths

**`KeySigner`: recommended.** You implement it. The SDK hands it canonical bytes and gets
back a signature, so the key stays in an HSM, cloud KMS, hardware wallet or remote signer
and never enters the SDK's address space. See [secure signing](docs/secure-signing.md)
for patterns.

**`ApiKey`: supported and hardened.** Use it for CI jobs, agents and workers that build a
client from one string.

- It parses every encoding the OpenMatter dashboard mints and holds the key in a
  zeroizing buffer. A seed never passes through an unzeroized temporary.
- `Debug`, `toString` and `%v` are redacted. It cannot be serialized with its key material
  (TypeScript's `toJSON` yields only the redacted form) and has no accessor for it.
- It rejects a phrase-less URI such as `//Alice`, which most SURI parsers silently
  resolve to the public development phrase.
- A signing client refuses mainnet without explicit confirmation.

Anything that can read the process can read the key; see
[what you are trading](docs/secure-signing.md).

**`*_insecure_dev_only`: unsupported.** Helpers such as
`Sr25519Signer::from_seed_insecure_dev_only` load a signer from raw material without any of
the `ApiKey` guarantees. They print a warning every time they are called. CI fails the
build if shipped library code references them; only their definition site, tests and
examples may. **Never use them outside development.**

## Supported versions

| Version | Supported |
|---|---|
| 2.3.x | ✅ |
| < 2.3 | ❌ |

Security fixes ship in the latest release of the current minor line, for every binding at
once, because one tag releases them all. See [`CHANGELOG.md`](CHANGELOG.md).
