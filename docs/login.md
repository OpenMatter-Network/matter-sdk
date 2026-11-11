# OpenMatter Login

OpenMatter Login gives a person a chain account from a sign-in they already have
(Google, Apple, any OpenID Connect provider), without a wallet and without any single
server holding their key.

The client is in the TypeScript core (`@openmatter-network/matter-sdk-core`), which runs
in a browser. Rust has the byte contract only; Python and Go do not have it yet
([parity](parity.md)).

## How it works

- **The key is a random 32-byte seed.** Its sr25519 account is the person's account.
- **The seed is a sealed secret.** It is sealed under the committee's joint key like any
  other [threshold secret](secrets.md), owned on chain by the seed's own account, under
  an AAD that names the app and the person.
- **The chain records who may open it.** `Logins.register_login` stores the envelope and
  a login record: `(app, identity) → account, secret id`. The identity is a hash of the
  app id and the token's issuer and subject, so the chain never stores an email address
  or a provider's user id, and the same person in two apps has two unrelated accounts.
- **The committee opens it for a valid sign-in token.** Each committee node verifies the
  provider's ID token itself (signature against the provider's published keys, issuer,
  audience, age) and checks the chain's login record before it returns its partial
  decryption. A threshold of partials recovers the seed in the client.
- **A token is bound to one session key.** The client makes a fresh sr25519 key for each
  sign-in and asks the provider for a token whose `nonce` is `loginNonce(sessionKey)`.
  Every committee request is signed by that key, so a token alone opens nothing.

## What you are trusting

- **The identity provider.** Whoever can obtain a valid token for a person in your app
  can recover that person's key. A compromised provider account is a compromised chain
  account. This is the same trust any "Sign in with …" button asks for.
- **A threshold of committee operators.** No single node can recover a seed: each holds
  one share of the committee key and returns only a partial decryption. But a threshold
  of nodes acting together can open any secret, including every login seed. The
  statement "no single party can reconstruct a key" is exactly as true as the committee
  operators are independent of one another. If one organization runs a threshold of the
  nodes, that organization can reconstruct keys.
- **Not the SDK's servers, and not the app.** There are none in the path. The app's
  backend never sees the seed; the app's *client code* does, as with any wallet.
- **The token itself, for ten minutes.** A node accepts a token for 600 seconds after
  it was issued. Someone who steals both a token and its session key within that window
  can sign in. Keep the session key in memory, and never log a token. The SDK does
  neither: no error message it raises contains a token.

The client verifies nothing about a token. `decodeIdTokenClaims` reads `iss` and `sub`
without checking a signature, only so the client can compute which login to ask for.
Never make an access decision from it.

## Registering (first sign-in)

```ts
import {
  ApiKey, FetchTransport, attestLoginRequest, collectLoginAttestations,
  decodeIdTokenClaims, loginAccount, loginNonce, prepareLoginRegistration,
  registerLogin, toHex, wipe,
} from "@openmatter-network/matter-sdk-core";

// 1. A session key, and a token bound to it.
const sessionKey = new ApiKey(toHex(crypto.getRandomValues(new Uint8Array(32))));
const idToken = await signInWithProvider({ nonce: loginNonce(sessionKey.accountId) }); // yours
const session = { idToken, requester: sessionKey.accountId, sign: (m: Uint8Array) => sessionKey.sign(m) };

// 2. A new seed, sealed for its own account.
const seed = crypto.getRandomValues(new Uint8Array(32));
const { iss, sub } = decodeIdTokenClaims(idToken);
const registration = prepareLoginRegistration({
  appId, issuer: iss, subject: sub, account: loginAccount(seed),
  jointPk, epoch, seed, genesis,               // chain reads, with your client
});

// 3. A threshold of committee nodes attest that a valid token asked for exactly this.
const attestations = await collectLoginAttestations(
  new FetchTransport(), nodes, await attestLoginRequest(registration, session), threshold,
);

// 4. Submit Logins.register_login SIGNED BY THE SEED'S ACCOUNT, then use the seed.
const args = registerLogin(registration, attestations);
```

`prepareLoginRegistration` refuses a seed that does not control `account`
(`LoginAccountMismatch`). `collectLoginAttestations` asks every node at once and returns
as soon as `threshold` distinct nodes have signed. It verifies no signature: the chain
checks each against the seated committee when the call is dispatched.

The registering account pays the fee, so it must hold a balance first.

## Signing in (every later time)

```ts
import {
  LOGIN_FOR_RUNTIME_API, decodeLoginRecord, loginForArgs, loginIdentity, oidcSigner, openLogin,
} from "@openmatter-network/matter-sdk-core";

const identity = loginIdentity(appId, iss, sub);
const record = decodeLoginRecord(await stateCall(LOGIN_FOR_RUNTIME_API, loginForArgs(appId, identity)));
if (!record) { /* not registered: register instead */ }

const seed = await openLogin(new FetchTransport(), oidcSigner({ appId, ...session }), {
  appId, identity, account: record.account, secretId: record.secretId,
  epoch, bindingId, capsule, ct,               // the secret, read as for any decrypt
  sharedA, blockHash, threshold, nodes,        // the committee at the secret's epoch
});
// ... use the seed (`new ApiKey(toHex(seed))`), then:
wipe(seed);
```

`openLogin` opens the envelope under the login AAD for `(appId, identity)` and returns
the seed only if it controls `record.account`; otherwise it wipes the bytes and throws
`LoginAccountMismatch`. If you recover a seed any other way, make that check yourself
with `loginAccount(seed)` before using it.

### How the token reaches the committee

A `Signer`'s answer (`RequestAuth`) has two optional fields, `id_token` and `app_id`,
beside `auth: "oidc"`. `oidcSigner` fills them on every answer, and `decrypt` copies them
into each `/partial-decrypt` request. The token is part of the signer's answer, so any
`Transport` carries it unchanged. Requests from every other signer are byte-identical
to before.

## Errors

Registration raises `LoginError`; branch on `kind`.

| `kind` | HTTP | Meaning | What to do |
|---|---|---|---|
| `already-registered` | 409 | The identity has a login in this app. | Read the record and sign in. |
| `token-refused` | 401, 403 | A node refused the token or the request signature. | Get a new token. Another node will answer the same. |
| `unavailable` | 503 | The node could not check, for example it cannot fetch the provider's keys. | Other nodes may still attest; retry later if too few did. |
| `rate-limited` | 429 | Too many requests. | Back off. |
| `transport` | other | Unreachable node, or a malformed or oversized response. | Retry. |
| `attestations` | — | Fewer than `threshold` nodes signed. `faults` lists each node's `kind`, `status` and reason. | Act on the faults. |
| `nonce-mismatch` | — | The token's `nonce` is not `loginNonce(requester)`. Raised locally, before any request. | Request the token with the right nonce. |
| `token-malformed` | — | Not a decodable JWT with `iss` and `sub`. | Check what the provider returned. |
| `account-mismatch` | — | `LoginAccountMismatch`: a seed does not control its account. | Do not use the seed. |

Sign-in raises `decrypt`'s `DecryptError` ([errors](errors.md)). A refused token appears
as `kind: "quorum"` with a `partial-decrypt 401` or `403` fault per node.

`Logins.register_login` can fail on chain with `AppNotFound`, `AppSuspended`,
`QuotaExhausted` (the app's registration quota is used up), `LoginAlreadyRegistered`,
`BindingNotOwnerBound` (the call was not signed by the account the seed was sealed
for), or `NotEnoughAttestations`.

## The byte contract

`loginIdentity`, `loginNonce`, `loginPayloadHash`, `loginAttestationPayload` and
`loginSeedAad` are computed identically by the committee, the chain and this SDK, and
pinned by [`testvectors/login.json`](../testvectors/README.md). In Rust they are
`matter_sdk::login`.

## Try it

[`examples/login-e2e`](../examples/login-e2e) runs the whole flow against a local dev
chain, a local committee and a local issuer.
