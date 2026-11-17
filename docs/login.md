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
- **Not the SDK's servers — and not the app's, unless the app is its own identity
  provider.** With a third-party provider (Google, Apple) no server of the app's is in
  the path. An issuer row is generic, though, and an app may register an issuer it runs
  itself: a service that proves control of a mailbox with a one-time code and signs the
  token (DataVizor's email sign-in, 2026-11; matter-org-meta ADR 0005). For those
  sign-ins the first bullet is about the app's operator: whoever holds that issuer's
  signing key, its mail-sending account, or the person's mailbox can obtain a token for
  the person. It is still one half of two — a token opens nothing without a threshold of
  the committee — and the issuer never sees a seed. In every case the app's backend
  never sees the seed; the app's *client code* does, as with any wallet.
- **What an issuer puts in `sub` is public.** Whether an identity is registered can be
  read from the chain by anyone who can compute it (app id, issuer, subject). An issuer
  whose subjects are guessable — an email address — lets anyone test a list of them.
  A first-party issuer should derive an opaque subject (a keyed hash of the address) and
  must then treat that key, and its normalisation of an address, as permanent: change
  either and every person gets a new account.
- **Whoever can change an app's issuers.** An app's issuer rows — which providers it
  accepts, and where each publishes its signing keys — are set by the chain's root
  origin, today one key. Whoever controls it can change a row and sign in as anyone
  registered through that issuer. From runtime spec 338 such a change is announced and
  **waits two days** once the app has logins (`IssuerChangeScheduled`; root can cancel
  it), so it can be seen before it is in force. Removing an issuer is immediate — that
  is the brake, with suspending the app — and putting the same issuer back waits like
  any change. A row for an issuer the app never had is in force at once: it makes new
  identities only.
- **Wherever an issuer's keys are fetched from** — unless they are pinned. A committee
  node fetches an issuer's keys from the issuer's own origin and nowhere else (a
  well-known provider's published location excepted), so whoever answers there — its
  DNS, its TLS key, its host — can sign as the issuer. For an issuer you run yourself,
  pin its public keys in the row instead (`logins.setIssuerKeys(appId, issuer, jwks)`,
  spec 338): nodes then verify against those and fetch nothing. A provider that rotates
  its keys on its own schedule cannot be pinned. Rotating pinned keys is a change like
  any other: pin the new key beside the old one two days before you sign with it.
- **Accounts are linkable to identities, by anyone.** An identity is an unkeyed hash of
  the app id, the issuer and the subject, and the record it resolves to is public. A
  provider whose subject is the same in every app (Google's is) lets anyone who knows
  a person's subject find their account in every app, and anyone who can compute a
  candidate identity can test whether it is registered. Nothing here hides that; decide
  whether it is acceptable for your app before you ship.
- **A seed is not an ordinary secret** (runtime spec 336). It is stored in the secret
  store but locked there: nobody opens it through `secrets` — not its account, not a
  key or a grantee acting for the account — and no `secrets` call shares, rewrites or
  deletes it. The committee opens it for a sign-in token and nothing else. Before 336 a
  scoped key holding Secrets: Read for the account could open it.
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
(`LoginAccountMismatch`). `collectLoginAttestations` asks `threshold` of the nodes, chosen
at random, and one more for each that does not sign: a token names the person (a
provider's may carry their email address) and every node asked reads it, so only as many
as are needed are asked. It verifies no signature: the chain checks each against the
seated committee when the call is dispatched.

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

## Rotating (a new account for the same sign-in)

A seed is a key, and a key that has leaked cannot be taken back. What the person still
holds is the sign-in. A rotation moves the login to a **new account** with a **new
seed** (runtime spec 337; committee nodes that attest rotations).

```ts
import {
  attestLoginRequest, collectLoginAttestations, loginAccount, prepareLoginRotation, rotateLogin,
} from "@openmatter-network/matter-sdk-core";

const record = decodeLoginRecord(await stateCall(LOGIN_FOR_RUNTIME_API, loginForArgs(appId, identity)));
const seed = crypto.getRandomValues(new Uint8Array(32));            // the NEW seed
const rotation = prepareLoginRotation({
  appId, issuer: iss, subject: sub, account: loginAccount(seed), jointPk, epoch, seed, genesis,
  from: record,                                                      // the login as it is now
});
const request = await attestLoginRequest(rotation, session);         // a fresh token and session key
const attestations = await collectLoginAttestations(transport, nodes, request, threshold);
const args = rotateLogin(rotation, attestations);
// Submit logins.rotateLogin(args…) SIGNED BY THE NEW ACCOUNT.
```

- A node attests a rotation only for a valid token of the identity, only at the
  generation after the one on chain, and only to an account other than the one the
  login has. A registration's attestation is never a rotation's.
- The app's pot pays for a login's rotation at most once per sponsor interval (seven
  days); a sooner one still lands if the new account can pay for it.
- **The account the login leaves is kept**, as the *previous* login: read it with
  `LOGIN_PREVIOUS_FOR_RUNTIME_API` (same arguments, same decoder) and open it with
  `openLogin` exactly as the current one. The same sign-in opens both, from any
  device, so what the previous account owns can be moved out after the rotation — no
  seed has to be kept anywhere in between. One previous login is kept, not a history:
  the next rotation removes the one before it, with its seed.
  Nothing re-seals a previous login's seed, so it opens only while the committee still
  keeps the key it was sealed under (eight epochs by default): move what it owns out
  promptly.
- When nothing is left in the previous account, the **current** account submits
  `logins.forgetPreviousLogin(appId, identity)`. After that nobody can open it.
- Rotating does **not** make the old key harmless. Whoever holds it still holds that
  account until what it owns has been moved. It gives the person an account nobody
  else holds. Suspending an app stops rotations as it stops registrations.

To keep a seed openable as committee keys change, its own account re-seals it:
`logins.resealLogin(appId, identity, payload, epoch)` — the same seed, sealed with
`encrypt` for the same account under a later epoch's key. No scoped key can make
either call.

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
| `rotation-conflict` | 409 | A rotation was asked for a login that is not one generation before it, or that already resolves to this account. | Read the record again. |
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
for), `NotEnoughAttestations`, `EpochNotSealable` (the committee has no finished key
for that epoch), or `CopiesNotRefused` — the network does not yet refuse a sealed
secret stored under an account it was not sealed for, so it registers no login at all;
read `SecretsApi_owner_binding_enforced` first. An unsponsorable call is refused at
submission with a bare `1010` fee error, so read every one of these before sending.
`rotate_login` adds `LoginNotFound`, `RotationKeepsAccount` and
`GenerationExhausted`.

## The byte contract

`loginIdentity`, `loginNonce`, `loginPayloadHash`, `loginAttestationPayload` and
`loginSeedAad` are computed identically by the committee, the chain and this SDK, and
pinned by [`testvectors/login.json`](../testvectors/README.md). In Rust they are
`matter_sdk::login`.

## Try it

[`examples/login-e2e`](../examples/login-e2e) runs the whole flow against a local dev
chain, a local committee and a local issuer.
