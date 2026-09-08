# Secure signing & secret handling

MatterVault does not decide where your signing key lives — **you do**. Recovered
**secrets never leak into logs**. This page is the integration guide for both.

There are two supported postures, and the difference between them is real:

| Posture | The key lives | Use when |
|---|---|---|
| **Bring your own signer** | in your HSM, cloud KMS, wallet, or remote signing service — never in the SDK's address space | production, and anywhere a key compromise would be expensive. **Recommended.** |
| **`apiKey`** | in your process, inside a hardened container the SDK provides | CI jobs, agents, ephemeral workers, single-file scripts — anywhere a client has to be built from one string |

Both are first-class constructors, not a primary and a fallback. Pick by where you
can keep the key, not by which is easier to type.

## The seam: signatures, not keys

Every authenticated operation goes through the same seam. The SDK produces canonical
bytes; something else turns them into a signature.

```
SDK  ──"sign these exact bytes"──►  your signer (HSM / KMS / wallet / remote / apiKey)
SDK  ◄────── signature ────────────
```

The canonical bytes come from the shared core, so every binding signs exactly what the
committee verifies — no transcript drift.

## Which trait do I implement?

Two traits, answering different questions. Implement the first unless you need the second.

| | You provide | The SDK derives | Implement it when |
|---|---|---|---|
| `KeySigner` | an account id and `sign(bytes)` | `/partial-decrypt` auth **and** extrinsic signatures | almost always — an HSM/KMS adapter is two methods |
| `Signer` | the finished auth fields for one request | nothing | you own the framing — notably the Ethereum/EIP-712 path, where there is no 32-byte substrate account id and the signer signs structured typed data |

- **Rust:** `impl KeySigner for MyHsm { fn account_id(&self) -> AccountId; fn sign(&self, msg: &[u8]) -> Result<[u8; 64]>; }`
  then pass it to `MatterClient::connect_with_signer`. `partial_decrypt_auth` does the
  SCALE `MultiSignature` framing, so it cannot drift per integration.
- **TypeScript:** pass `keySigner({ accountId, sign })`, or `substrateSigner(accountId, sign)`
  when the key is a closure. `sign` may be async.

`sign` is deliberately allowed to fail, and in Rust deliberately synchronous — a signer
that must do network I/O should block. That keeps the trait object-safe, which is what
lets a read-only client, an `apiKey` client, and an HSM client all be the same type.

## Patterns by key location

| Key lives in | How to wire it |
|---|---|
| Cloud KMS (AWS/GCP/Azure) | Implement `Signer`/`sign` to call the KMS sign API. KMS must support the curve; for sr25519, use a signing service or a KMS-sealed seed loaded into an enclave. |
| HSM (PKCS#11) | `sign` calls `C_Sign`. The key is non-exportable. |
| Hardware / browser wallet | `sign` triggers the wallet prompt (e.g. `eth_signTypedData_v4` for the Ethereum path, or a Substrate extension). |
| Remote signer service | `sign` makes an authenticated RPC to your signer; the key never reaches the app host. |

> The substrate auth path wraps an sr25519 signature as a SCALE `MultiSignature`
> (`0x01 ‖ sig`) and the account as a 32-byte `AccountId`. The SDK does that framing;
> your callback only produces the 64-byte sr25519 signature.

## The `apiKey` path

An OpenMatter API key is an sr25519 secret in one of three encodings — a `0x` 32-byte
mini-secret, a BIP39 mnemonic, or a full SURI with derivation junctions — optionally
prefixed with its scheme (`sr25519:…`). The same three encodings the dashboard mints
are pinned across every binding by `testvectors/api_keys.json`.

```
MATTER_API_KEY=0xfac7…479e   # never in argv, never in source
```

### What you are trading

**Stated plainly.** An `apiKey` is a private key your process holds. Anything that can
read your process — a core dump, a debugger, a malicious transitive dependency, a heap
snapshot from a crash reporter, `root` reading `/proc` — can read it, and whoever holds
it can act with it until you revoke it. A KMS- or HSM-backed signer has no such window:
the key is never in your address space, so compromising the process buys an attacker
*use* of the key for as long as they hold the process, not *possession* of it forever.
That difference is why bring-your-own-signer is still the recommendation.

What has changed is **how much a leaked key is worth**. A member-tied key is not an
account with authority of its own — see [Scoped keys](#scoped-keys) below. It is a
delegate holding a `ScopeSet` on its member's account, and a leak is bounded by that
set: a key scoped `deployments:w` cannot move a token, touch staking, vote, read a
secret, or mint another key, however long the attacker holds it. Revocation is one
extrinsic and takes effect on the next request. That is a materially better trade than
the old project-tied key, which was an account you funded and grants you attached.

What `apiKey` buys in exchange is that a client can be built from one string, which is
what makes CI jobs, agents, ephemeral workers, and single-file scripts possible at all.
We ship it because the alternative is worse, not because it is safe: without it, every
one of those workloads hand-rolls an in-memory signer with no zeroization, a `Debug`
impl that prints the key, and a `toJSON` that ships it to a log aggregator. Our own
audit flagged exactly that drift (MV-M3). A supported, hardened container is the answer
to that finding. It is a supported path, not a blessed default.

### The guardrails

Every row is a property of the type itself, in all four bindings — not advice you have
to remember:

| Guardrail | What it does |
|---|---|
| **Zeroized** | The mini-secret and every intermediate derivation live in zeroizing buffers and wipe on drop. No hex or SURI copy of the seed is left in freed heap — the MV-M3 lesson applied to a path we expect production traffic on. |
| **Redacted** | No formatting path prints the key, including from inside a struct, slice, or map: `toString`, `repr`, `String()`, `%v`, and `%+v` render `ApiKey(sr25519, 0x…, <redacted>)`, and Rust's `Debug` renders the struct form with `material: "<redacted>"`. |
| **Non-serializable** | Key material cannot reach a config dump, a structured-log field, or a crash report by accident: no `Serialize` in Rust, no pickle/copy in Python. Go's `MarshalJSON` *errors* rather than emitting a placeholder, because a silent placeholder would pass code review. TypeScript's `toJSON` exists but yields only the redacted display string, so `JSON.stringify` never sees the key. |
| **No secret accessor** | There is no method that returns the key bytes. The only outputs are the public account id and signatures. In TypeScript and Go the material never leaves Rust memory at all. |
| **Not clonable** | Rust's `ApiKey` is not `Clone`; share one with `Arc`. One key, one place to wipe. |
| **Errors never echo the key** | A rejection names *what* was wrong, never any part of the input. Upstream parsers are not careful here — `subxt-signer` renders `Invalid character 'g' at position 5`, disclosing a character of the secret and its offset — so the SDK never forwards an upstream source. |
| **Testnet by default, mainnet by consent** | A client defaults to testnet, and a *signing* client refuses to connect to mainnet without `MATTER_CONFIRM=yes` or `confirm_mainnet`. The check is on what the endpoint actually serves, so pointing a testnet config at a mainnet URL still trips. An accidental production submit takes two mistakes, not one. |
| **No implicit dev account** | A phrase-less URI like `//Alice` is **rejected**. Most SURI parsers silently substitute the public well-known development phrase, so an unset environment variable would otherwise mint a working, globally-controlled signer. |

Guardrails constrain accidents, not attackers. None of them help once the process is
compromised — see the trade above.

### Operating an apiKey safely

1. **Scope it, narrowly.** Mint it with the smallest `ScopeSet` that does the job, and
   remember Read and Write are independent bits: a deployment agent wants
   `deployments:w`, not `deployments:rw`, and a policy reader wants a Read bit and no
   Write bit at all. Widening later is one call. A leak is bounded by the set.
2. **Rotate it.** Rotation is `keys.authorize` for the new key and `keys.revoke` for
   the old — *not* a re-encryption. Ciphertext is bound to the committee's joint key,
   not to yours, so rotating a signer costs two extrinsics and no cryptography. One
   caveat with teeth: a key holding `secrets:w` can `grantAccess` **to itself**, and
   those grants **survive revocation**. Containment there is revoke, then sweep the
   key's `User` grants over the member's secrets, then rotate.
3. **Treat it as a bearer credential.** Unlike an HSM key it can leak by screenshot,
   paste, a committed `.env`, or a CI job printing its environment. Rotate on
   suspicion, not on proof.
4. **Don't share one across workloads.** Two services on one key means one leak
   revokes both.
5. **Read it from the environment or a secret manager, never argv.** The SDK's
   examples and errors only ever demonstrate the env path, so keys stay out of shell
   history and `ps` output.

## Scoped keys

Runtime spec 322 moved where an API key's authority lives. A key is still a raw sr25519
keypair, but it is now registered by the **member it acts for**, as a `pallet_proxy`
definition of type `Scoped(ScopeSet)` on that member's account. Every call it makes is
dispatched as `proxy.proxy(member, null, call)` and runs **as the member**: ownership
and role checks evaluate against them, gas is paid by their billing org or by them, and
the runtime admits the call only if the key's set covers what that call requires.

Three consequences worth internalising:

- **The key's own account has no authority and no balance.** A directly signed call
  from a member-tied key is refused in the pool for want of fees, not for want of
  permission — which is why the SDK checks scopes locally and tells you which one is
  missing, instead of letting you read a fee complaint and go looking for a funding bug.
- **The member is accountable for the key.** `deployments:w` commits their balance to
  compute settlement; `organization:w` is Admin-equivalent. There is no per-key spend
  cap on chain.
- **Read and Write are independent, and only `secrets:r` is enforced on chain.**
  `SecretsApi_is_authorized` answers for a key exactly as it would for its member, so a
  key with `secrets:r` no longer needs a per-secret grant to decrypt. Every other Read
  bit is advisory until the service that serves that data enforces it.

The client resolves all of this once at connect and tells you what it found:

```
INFO: acting for 5GrwvaEF… with scopes deployments:w, secrets:r
```

`client.mode()`, `client.principal()` and `client.scopes()` expose it. A key that
resolves to `Direct` when you expected delegation is revoked, or minted against a
different network — that log line is the first thing to check.

Minting and revoking are **member-signed**; a key can never call them on itself,
because the roster calls are on the runtime's never-admitted list precisely so a key
cannot widen its own authority:

```rust
client.keys().authorize(agent_account, "deployments:w".parse()?).await?;
client.keys().revoke(agent_account).await?;
```

Legacy project-tied keys (`orgs().authorize_secrets_agent`) keep working unchanged.
Migrating one is: revoke the legacy key, mint a member-tied one.

## Dev-only local keys (and why they are still named that)

The SDK still ships two shame-named constructors:

- Rust: `Sr25519Signer::from_seed_insecure_dev_only(&seed)` (raw 32-byte seed) or
  `Sr25519Signer::from_uri_insecure_dev_only(uri)` (`0x`-hex seed, BIP39 mnemonic, or SURI)

Now that a key-holding path is supported, the obvious question is why these keep the
name. The name was never about *"a key is in this process"* — it is about *"this key is
not being looked after."* These constructors accept raw material the caller already
holds in an ordinary, non-zeroizing buffer; they hand it to a signer with none of the
container guarantees above; and they exist to serve doctests and demos where the seed
is a literal `[7u8; 32]`. `apiKey` is the hardened container they deliberately are not.

The rule of thumb: **if a key is going to live in your process anyway, it should live in
an `apiKey`.** These stay for tests, doctests, and the offline demos; they keep their
runtime warning; and the CI check that fails a release target depending on them stays
exactly as it is. Nothing about them got safer — the difference is that there is now
somewhere better to go.

## Secret hygiene rules

1. **A signing key is the highest-value secret in the system.** Everything below is
   about recovered plaintext; this rule is about the key that authorizes recovering it.
   Prefer a signer you own. If you use an `apiKey`, read it from the environment or a
   secret manager, scope it, and rotate on suspicion.
2. **Recovered plaintext is sensitive.** Rust returns it as a zeroizing `Plaintext`
   that wipes on drop and redacts its `Debug`. wasm/Python/Go return raw bytes (the
   runtime has no zeroizing buffer) — keep them short-lived, don't copy them around,
   and overwrite when done.
3. **Never log secrets.** The SDK never logs plaintext, keys, or signatures. Don't add
   logging that does. Follow quiet-success / loud-typed-failure.
4. **Use the AAD registry.** Seal and store with the same `Aad` tag; a mismatch is a
   silent decrypt failure. The enum makes a typo a compile error.
5. **Freshness and recipient are enforced.** The request binds a recent `block_hash`
   (and, on the Ethereum path, `valid_until`) plus the responding node's `dkg_index`, so
   a captured request can't be replayed at another secret, at a different committee node,
   or after its window. The SDK signs once per node — each node verifies against its own
   index (MV-C1).

## Threat boundaries

See [`SECURITY.md`](../SECURITY.md) for the full threat model. In one line: a stolen
ciphertext or a single compromised committee node reveals nothing; a quorum of
colluding nodes, or a stolen signer, does. Pick `t`/`n` and protect your signer
accordingly.
