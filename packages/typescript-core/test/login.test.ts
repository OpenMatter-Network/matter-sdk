// OpenMatter Login: the byte contract replayed from testvectors/login.json, and
// the client shell around it against fake committees. No socket, no chain.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  ApiKey,
  attestLoginRequest,
  bindingCommitsTo,
  collectLoginAttestations,
  decodeIdTokenClaims,
  decodeLoginRecord,
  decrypt,
  FetchTransport,
  LoginAccountMismatch,
  loginAccount,
  loginAttestationPayload,
  LoginError,
  loginForArgs,
  loginIdentity,
  loginNonce,
  loginPayloadHash,
  loginSeedAad,
  oidcSigner,
  openLogin,
  prepareLoginRegistration,
  registerLogin,
  signingPayload,
  substrateSigner,
  verifyPlaintextProof,
  LOGIN_FIRST_GENERATION,
  type AttestLoginRequest,
  type AttestLoginResponse,
  type CommitteeNode,
  type Health,
  type PartialDecryptRequest,
  type PartialDecryptResponse,
  type Signer,
  type Transport,
} from "../src/index.js";
import { fromHex, toHex } from "../src/util.js";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const load = (name: string) => JSON.parse(readFileSync(resolve(vectorsDir, name), "utf8"));
const vectors = load("login.json");
const fixture = load("open_secret.json");
const bare = (bytes: Uint8Array) => toHex(bytes).slice(2);

const APP_ID = new Uint8Array(32).fill(0xa1);
const REQUESTER = new Uint8Array(32).fill(0x22);
const ISSUER = "https://issuer.example";
const SUBJECT = "user-1";

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A structurally valid, unsigned token: only the committee verifies signatures. */
function tokenFor(requester: Uint8Array, claims: Record<string, unknown> = {}): string {
  return [
    b64url({ alg: "RS256", typ: "JWT" }),
    b64url({ iss: ISSUER, sub: SUBJECT, aud: "client-1", nonce: loginNonce(requester), iat: 1000, exp: 1300, ...claims }),
    "c2lnbmF0dXJl",
  ].join(".");
}
const TOKEN = tokenFor(REQUESTER);
const fakeSign = (seen: Uint8Array[] = []) => (payload: Uint8Array) => {
  seen.push(payload);
  return new Uint8Array(64).fill(0x5a);
};

describe("login byte contract conformance", () => {
  it("has not lost rows", () => {
    expect(vectors.identity.length).toBeGreaterThanOrEqual(4);
    for (const section of ["nonce", "payload_hash", "attestation", "seed_aad"]) {
      expect(vectors[section].length).toBeGreaterThan(0);
    }
  });

  it.each(vectors.identity)("identity of iss=$issuer sub=$subject", (c: any) => {
    expect(bare(loginIdentity(fromHex(c.app_id_hex), c.issuer, c.subject))).toBe(c.identity_hex);
  });

  it.each(vectors.nonce)("nonce for $requester_hex", (c: any) => {
    expect(loginNonce(fromHex(c.requester_hex))).toBe(c.nonce);
  });

  it.each(vectors.payload_hash)("payload hash $payload_hash_hex", (c: any) => {
    const got = loginPayloadHash(
      fromHex(c.binding_id_hex),
      fromHex(c.capsule_hex),
      fromHex(c.proof_hex),
      fromHex(c.ct_hex),
    );
    expect(bare(got)).toBe(c.payload_hash_hex);
  });

  it.each(vectors.attestation)("attestation payload, generation $generation", (c: any) => {
    const got = loginAttestationPayload(
      fromHex(c.genesis_hex),
      fromHex(c.app_id_hex),
      fromHex(c.identity_hex),
      fromHex(c.account_hex),
      fromHex(c.payload_hash_hex),
      c.generation,
    );
    expect(bare(got)).toBe(c.payload_hex);
  });

  it.each(vectors.seed_aad)("seed aad $aad_hex", (c: any) => {
    expect(bare(loginSeedAad(fromHex(c.app_id_hex), fromHex(c.identity_hex)))).toBe(c.aad_hex);
  });

  it("names a wrong-width input", () => {
    const short = new Uint8Array(31);
    expect(() => loginIdentity(short, "iss", "sub")).toThrow(/app_id must be 32 bytes, got 31/);
    expect(() => loginNonce(short)).toThrow(/requester must be 32 bytes/);
    expect(() => loginSeedAad(APP_ID, short)).toThrow(/identity must be 32 bytes/);
    expect(() => loginAttestationPayload(short, APP_ID, APP_ID, APP_ID, APP_ID, 0)).toThrow(/genesis must be 32 bytes/);
  });

  // The account of a seed is the sr25519 derivation every binding shares.
  it("derives a seed's account like an API key does", () => {
    for (const c of load("seed_formats.json").cases) {
      expect(bare(loginAccount(fromHex(c.mini_secret_hex)))).toBe(c.account_id_hex);
    }
    expect(() => loginAccount(new Uint8Array(31))).toThrow(/seed must be 32 bytes/);
  });
});

describe("decodeIdTokenClaims", () => {
  it("reads the claims a client needs, unverified", () => {
    expect(decodeIdTokenClaims(TOKEN)).toEqual({
      iss: ISSUER,
      sub: SUBJECT,
      aud: "client-1",
      nonce: loginNonce(REQUESTER),
      iat: 1000,
      exp: 1300,
    });
  });

  it("keeps a multi-audience claim and tolerates absent optional claims", () => {
    const token = `${b64url({})}.${b64url({ iss: "i", sub: "s", aud: ["a", "b"] })}.x`;
    expect(decodeIdTokenClaims(token)).toEqual({ iss: "i", sub: "s", aud: ["a", "b"] });
  });

  it("decodes non-ASCII claims as UTF-8", () => {
    const token = `${b64url({})}.${b64url({ iss: "https://é.example", sub: "ü", aud: "a" })}.x`;
    expect(decodeIdTokenClaims(token).iss).toBe("https://é.example");
  });

  it.each([
    ["empty", ""],
    ["two segments", "a.b"],
    ["four segments", "a.b.c.d"],
    ["not base64url", "a.@@@.c"],
    ["not JSON", `a.${Buffer.from("nope").toString("base64url")}.c`],
    ["not an object", `a.${b64url(["iss"])}.c`],
    ["no iss", `a.${b64url({ sub: "s", aud: "a" })}.c`],
    ["numeric sub", `a.${b64url({ iss: "i", sub: 7, aud: "a" })}.c`],
    ["non-string aud entry", `a.${b64url({ iss: "i", sub: "s", aud: ["a", 1] })}.c`],
    ["non-numeric exp", `a.${b64url({ iss: "i", sub: "s", exp: "soon" })}.c`],
  ])("refuses a malformed token: %s", (_name, token) => {
    const err = (() => {
      try {
        return decodeIdTokenClaims(token);
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoginError);
    expect((err as LoginError).kind).toBe("token-malformed");
  });
});

describe("oidcSigner", () => {
  const request = { secretId: 7n, subset: [1, 2, 3], recipientIndex: 2, blockHash: new Uint8Array(32).fill(9) };

  it("answers with the token, the app and a signature over the decrypt payload", async () => {
    const seen: Uint8Array[] = [];
    const signer = oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: fakeSign(seen) });
    expect(signer.authScheme()).toBe("oidc");
    const auth = await signer.authorize(request);
    expect(auth).toEqual({
      auth: "oidc",
      requester: toHex(REQUESTER),
      // SCALE MultiSignature::Sr25519, as the substrate path frames it.
      signature: "0x01" + "5a".repeat(64),
      id_token: TOKEN,
      app_id: toHex(APP_ID),
    });
    expect(seen).toEqual([signingPayload(7n, [1, 2, 3], request.blockHash, 2)]);
  });

  it("refuses a token minted for another key, before any request", () => {
    const other = new Uint8Array(32).fill(0x23);
    const err = (() => {
      try {
        return oidcSigner({ appId: APP_ID, idToken: tokenFor(other), requester: REQUESTER, sign: fakeSign() });
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(LoginError);
    expect((err as LoginError).kind).toBe("nonce-mismatch");
  });

  it("refuses a wrong-width app id or requester", () => {
    const base = { appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: fakeSign() };
    expect(() => oidcSigner({ ...base, appId: new Uint8Array(31) })).toThrow(/appId must be 32 bytes/);
    expect(() => oidcSigner({ ...base, requester: new Uint8Array(33) })).toThrow(/requester must be 32 bytes/);
  });
});

// A committee that replays the open_secret fixture and records what it was sent.
const byIndex = new Map<number, any>((fixture.subset as number[]).map((idx, i) => [idx, fixture.partials[i]]));
class RecordingCommittee implements Transport {
  sent: PartialDecryptRequest[] = [];
  async health(): Promise<Health> {
    return { status: "active", epoch: fixture.epoch };
  }
  async partialDecrypt(endpoint: string, req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
    this.sent.push(req);
    const index = Number(endpoint.split("-").at(-1));
    const p = byIndex.get(index);
    return { node_index: index, partial: "0x" + p.partial_hex, proof: "0x" + p.proof_hex, served_epoch: fixture.epoch };
  }
}
const fixtureNodes = (): CommitteeNode[] =>
  (fixture.subset as number[]).map((index) => ({
    index,
    endpoint: `http://node-${index}`,
    shareCommitment: fromHex(byIndex.get(index).commitment_hex),
  }));
const fixtureParams = () => ({
  secretId: BigInt(fixture.secret_id),
  epoch: fixture.epoch as number,
  bindingId: fromHex(fixture.binding_id_hex),
  aad: fromHex(fixture.aad_hex),
  capsule: fromHex(fixture.capsule_hex),
  ct: fromHex(fixture.ct_hex),
  sharedA: fromHex(fixture.shared_a_hex),
  blockHash: new Uint8Array(32),
  threshold: Number(fixture.meta.t),
  nodes: fixtureNodes(),
});

describe("the partial-decrypt request", () => {
  it("carries auth, id_token and app_id from an oidc signer", async () => {
    const committee = new RecordingCommittee();
    const signer = oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: fakeSign() });
    await decrypt(committee, signer, fixtureParams());
    expect(committee.sent).toHaveLength(Number(fixture.meta.t));
    for (const req of committee.sent) {
      expect(req).toMatchObject({ auth: "oidc", id_token: TOKEN, app_id: toHex(APP_ID), requester: toHex(REQUESTER) });
    }
  });

  // Pinned: a committee node of any version must not see one byte move for the
  // substrate path because the oidc path exists.
  it("is byte-identical to before for a substrate signer", async () => {
    const committee = new RecordingCommittee();
    const signer = substrateSigner(new Uint8Array(32).fill(0x11), fakeSign());
    await decrypt(committee, signer, fixtureParams());
    const first = committee.sent[0]!;
    const { lagrange_coeff, ...rest } = first;
    expect(lagrange_coeff).toMatch(/^0x[0-9a-f]+$/);
    expect(Object.keys(JSON.parse(JSON.stringify(first)))).toEqual([
      "secret_id",
      "subset",
      "lagrange_coeff",
      "requester",
      "block_hash",
      "signature",
      "auth",
    ]);
    expect(JSON.stringify(rest)).toBe(
      `{"secret_id":"0x${BigInt(fixture.secret_id).toString(16).padStart(32, "0")}",` +
        `"subset":[${(fixture.subset as number[]).join(",")}],` +
        `"requester":"0x${"11".repeat(32)}",` +
        `"block_hash":"0x${"00".repeat(32)}",` +
        `"signature":"0x01${"5a".repeat(64)}",` +
        `"auth":"substrate"}`,
    );
  });
});

function fetchAnswering(status: number, body: string, seen: Array<{ url: string; init: RequestInit }> = []): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(url), init: init ?? {} });
    return new Response(body, { status });
  }) as typeof fetch;
}

const ATTEST_REQUEST: AttestLoginRequest = {
  app_id: toHex(APP_ID),
  id_token: TOKEN,
  account: "0x" + "33".repeat(32),
  payload_hash: "0x" + "44".repeat(32),
  requester: toHex(REQUESTER),
  signature: "0x" + "5a".repeat(64),
};
const attestation = (byte: number): AttestLoginResponse => ({
  node_account: "0x" + byte.toString(16).padStart(2, "0").repeat(32),
  signature: "0x" + "ee".repeat(64),
  crypto_protocol_version: 2,
});

describe("FetchTransport.attestLogin", () => {
  it("posts the request body to /attest-login under a deadline", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const transport = new FetchTransport(fetchAnswering(200, JSON.stringify(attestation(1)), seen));
    expect(await transport.attestLogin("http://node-1/", ATTEST_REQUEST)).toEqual(attestation(1));
    expect(seen[0]!.url).toBe("http://node-1/attest-login");
    expect(seen[0]!.init.method).toBe("POST");
    expect(JSON.parse(seen[0]!.init.body as string)).toEqual(ATTEST_REQUEST);
    expect(seen[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([
    [409, "already-registered"],
    [401, "token-refused"],
    [403, "token-refused"],
    [429, "rate-limited"],
    [503, "unavailable"],
    [400, "transport"],
    [500, "transport"],
  ] as const)("maps %i to %s and keeps the status", async (status, kind) => {
    const transport = new FetchTransport(fetchAnswering(status, "refused"));
    const err = await transport.attestLogin("http://node-1", ATTEST_REQUEST).catch((e) => e);
    expect(err).toBeInstanceOf(LoginError);
    expect(err.kind).toBe(kind);
    expect(err.status).toBe(status);
    expect(err.message).toContain(String(status));
    expect(err.message).toContain("http://node-1");
  });

  it("refuses a body over the cap", async () => {
    const big = JSON.stringify({ ...attestation(1), padding: "x".repeat(512) });
    const transport = new FetchTransport(fetchAnswering(200, big), { maxResponseBytes: 64 });
    const err = await transport.attestLogin("http://node-1", ATTEST_REQUEST).catch((e) => e);
    expect(err).toBeInstanceOf(LoginError);
    expect(err.kind).toBe("transport");
    expect(err.message).toMatch(/exceeded/);
  });

  it("never repeats the token, even when the node echoes it", async () => {
    const transport = new FetchTransport(fetchAnswering(401, `bad token ${TOKEN}`));
    const err = await transport.attestLogin("http://node-1", ATTEST_REQUEST).catch((e) => e);
    expect(err.message).not.toContain(TOKEN);
    expect(err.message).toContain("bad token");
  });
});

type Answer = AttestLoginResponse | Error | Promise<AttestLoginResponse>;
const attestors = (answers: Record<string, Answer>) => ({
  asked: [] as string[],
  async attestLogin(endpoint: string): Promise<AttestLoginResponse> {
    this.asked.push(endpoint);
    const answer = answers[endpoint]!;
    if (answer instanceof Error) throw answer;
    return answer;
  },
});
const endpoints = (n: number) => Array.from({ length: n }, (_, i) => ({ endpoint: `http://node-${i + 1}` }));
const refusal = (status: number, kind: LoginError["kind"]) =>
  new LoginError(kind, `attest-login ${status} from a node`, { status });

describe("collectLoginAttestations", () => {
  it("returns threshold attestations from distinct nodes", async () => {
    const transport = attestors({
      "http://node-1": attestation(1),
      "http://node-2": attestation(2),
      "http://node-3": attestation(3),
    });
    const got = await collectLoginAttestations(transport, endpoints(3), ATTEST_REQUEST, 2);
    expect(got).toHaveLength(2);
    expect(new Set(got.map((a) => toHex(a.nodeAccount))).size).toBe(2);
    expect(got[0]!.signature).toEqual(new Uint8Array(64).fill(0xee));
    expect(transport.asked).toHaveLength(3);
  });

  it("does not count one node account twice", async () => {
    const transport = attestors({
      "http://node-1": attestation(1),
      "http://node-2": attestation(1),
      "http://node-3": refusal(503, "unavailable"),
    });
    const err = await collectLoginAttestations(transport, endpoints(3), ATTEST_REQUEST, 2).catch((e) => e);
    expect(err).toBeInstanceOf(LoginError);
    expect(err.kind).toBe("attestations");
    expect(err.faults).toEqual([
      expect.objectContaining({ endpoint: "http://node-2", detail: expect.stringMatching(/already counted/) }),
      expect.objectContaining({ endpoint: "http://node-3", status: 503, kind: "unavailable" }),
    ]);
  });

  it("lists every node's fault when too few sign", async () => {
    const transport = attestors({
      "http://node-1": attestation(1),
      "http://node-2": refusal(401, "token-refused"),
      "http://node-3": new TypeError("fetch failed"),
      "http://node-4": { node_account: "0x1234", signature: "0x00", crypto_protocol_version: 2 },
    });
    const err = await collectLoginAttestations(transport, endpoints(4), ATTEST_REQUEST, 3).catch((e) => e);
    expect(err.kind).toBe("attestations");
    expect(err.message).toMatch(/need 3 attestations, got 1/);
    expect(err.faults.map((f: any) => [f.endpoint, f.kind, f.status])).toEqual([
      ["http://node-2", "token-refused", 401],
      ["http://node-3", "transport", undefined],
      ["http://node-4", "transport", undefined],
    ]);
    expect(err.message).toContain("http://node-3");
    expect(err.message).toContain("fetch failed");
  });

  it("short-circuits on a 409 as already-registered", async () => {
    const never = new Promise<AttestLoginResponse>(() => {});
    const transport = attestors({
      "http://node-1": never,
      "http://node-2": refusal(409, "already-registered"),
      "http://node-3": never,
    });
    const err = await collectLoginAttestations(transport, endpoints(3), ATTEST_REQUEST, 2).catch((e) => e);
    expect(err).toBeInstanceOf(LoginError);
    expect(err.kind).toBe("already-registered");
    expect(err.status).toBe(409);
  });

  it("does not wait for a slow node once the threshold is met", async () => {
    const transport = attestors({
      "http://node-1": attestation(1),
      "http://node-2": new Promise<AttestLoginResponse>(() => {}),
      "http://node-3": attestation(3),
    });
    const got = await collectLoginAttestations(transport, endpoints(3), ATTEST_REQUEST, 2);
    expect(got.map((a) => a.nodeAccount[0])).toEqual([1, 3]);
  });

  it("refuses an impossible threshold without asking anyone", async () => {
    const transport = attestors({ "http://node-1": attestation(1) });
    const err = await collectLoginAttestations(transport, endpoints(1), ATTEST_REQUEST, 2).catch((e) => e);
    expect(err.kind).toBe("attestations");
    expect(err.faults).toEqual([]);
    expect(transport.asked).toEqual([]);
    await expect(collectLoginAttestations(transport, endpoints(1), ATTEST_REQUEST, 0)).rejects.toThrow(/threshold/);
  });
});

describe("prepareLoginRegistration", () => {
  const seed = fromHex(load("seed_formats.json").cases[0].mini_secret_hex);
  const account = loginAccount(seed);
  const genesis = new Uint8Array(32).fill(0x42);
  const jointPk = fromHex(fixture.joint_pk_hex);
  const prepare = () =>
    prepareLoginRegistration({
      appId: APP_ID,
      issuer: ISSUER,
      subject: SUBJECT,
      account,
      jointPk,
      epoch: fixture.epoch,
      seed,
      genesis,
    });

  it("seals the seed for its account and commits to the envelope", () => {
    const reg = prepare();
    const { envelope } = reg;
    // Expectations come from the contract functions pinned above, never from `reg`.
    const identity = loginIdentity(APP_ID, ISSUER, SUBJECT);
    const payloadHash = loginPayloadHash(envelope.bindingId, envelope.capsule, envelope.proof, envelope.ct);
    expect(reg.identity).toEqual(identity);
    expect(bindingCommitsTo(account, envelope.bindingId)).toBe(true);
    expect(reg.payloadHash).toEqual(payloadHash);
    expect(reg.attestationPayload).toEqual(
      loginAttestationPayload(genesis, APP_ID, identity, account, payloadHash, LOGIN_FIRST_GENERATION),
    );
    expect(verifyPlaintextProof(jointPk, envelope.capsule, envelope.proof, envelope.bindingId, fixture.epoch)).toBe(true);
    expect(reg).toMatchObject({ appId: APP_ID, account, epoch: fixture.epoch });
  });

  it("uses a fresh salt each time", () => {
    expect(toHex(prepare().envelope.bindingId)).not.toBe(toHex(prepare().envelope.bindingId));
  });

  it("refuses to seal a seed for an account it does not control", () => {
    const other = new Uint8Array(32).fill(0x77);
    expect(() =>
      prepareLoginRegistration({ appId: APP_ID, issuer: ISSUER, subject: SUBJECT, account: other, jointPk, epoch: 1, seed, genesis }),
    ).toThrow(LoginAccountMismatch);
  });

  it("builds a signed attest-login request and the register_login arguments", async () => {
    const reg = prepare();
    const seen: Uint8Array[] = [];
    const req = await attestLoginRequest(reg, { idToken: TOKEN, requester: REQUESTER, sign: fakeSign(seen) });
    expect(req).toEqual({
      app_id: toHex(APP_ID),
      id_token: TOKEN,
      account: toHex(account),
      payload_hash: toHex(reg.payloadHash),
      requester: toHex(REQUESTER),
      signature: "0x" + "5a".repeat(64),
    });
    expect(seen).toEqual([reg.attestationPayload]);

    const attestations = [{ nodeAccount: new Uint8Array(32).fill(1), signature: new Uint8Array(64).fill(2) }];
    expect(registerLogin(reg, attestations)).toEqual({
      appId: APP_ID,
      identity: reg.identity,
      payload: reg.envelope,
      epoch: fixture.epoch,
      attestations: [[attestations[0]!.nodeAccount, attestations[0]!.signature]],
    });
  });
});

describe("the login record read", () => {
  const identity = new Uint8Array(32).fill(0x1d);
  const account = new Uint8Array(32).fill(0x33);

  it("frames the LoginsApi_login_for argument", () => {
    expect(loginForArgs(APP_ID, identity)).toBe("0x" + "a1".repeat(32) + "1d".repeat(32));
  });

  it("decodes Some(record) and None", () => {
    // SCALE: 0x01 ‖ AccountId32 ‖ u128 LE ‖ u32 LE.
    const some = "0x01" + "33".repeat(32) + "2a" + "00".repeat(14) + "01" + "07000000";
    expect(decodeLoginRecord(some)).toEqual({ account, secretId: 42n + (1n << 120n), generation: 7 });
    expect(decodeLoginRecord(fromHex("0x00"))).toBeNull();
  });

  it.each(["0x", "0x02", "0x01" + "33".repeat(32), "0x00ff"])("refuses malformed SCALE %s", (hex) => {
    expect(() => decodeLoginRecord(hex)).toThrow(LoginError);
  });
});

describe("openLogin", () => {
  // The fixture secret stands in for a sealed seed: its AAD is not a login AAD,
  // so a real open must fail authentication rather than return bytes.
  const oidc = () => oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: fakeSign() });
  const { aad: _aad, ...params } = fixtureParams();
  const login = { ...params, appId: APP_ID, identity: new Uint8Array(32).fill(0x1d), account: new Uint8Array(32).fill(0x33) };

  it("opens under the login seed AAD, never one the caller supplies", async () => {
    const err = await openLogin(new RecordingCommittee(), oidc(), login).catch((e) => e);
    expect(err.kind).toBe("crypto");
    expect(err.message).toMatch(/AEAD/);
  });

  it("refuses a signer that carries no sign-in token", async () => {
    const committee = new RecordingCommittee();
    const signer: Signer = substrateSigner(REQUESTER, fakeSign());
    const err = await openLogin(committee, signer, login).catch((e) => e);
    expect(err).toBeInstanceOf(LoginError);
    expect(committee.sent).toEqual([]);
  });
});

describe("the token never reaches a message", () => {
  it("in any error this module raises", async () => {
    const raised: unknown[] = [];
    const attempt = async (fn: () => unknown) => {
      try {
        await fn();
      } catch (e) {
        raised.push(e);
      }
    };
    const other = new Uint8Array(32).fill(0x23);
    await attempt(() => oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: other, sign: fakeSign() }));
    await attempt(() => oidcSigner({ appId: new Uint8Array(3), idToken: TOKEN, requester: REQUESTER, sign: fakeSign() }));
    await attempt(() => decodeIdTokenClaims(TOKEN + ".extra"));
    await attempt(() => decodeIdTokenClaims(TOKEN.replace(".", ".@")));
    await attempt(() => new FetchTransport(fetchAnswering(403, TOKEN)).attestLogin("http://n", ATTEST_REQUEST));
    await attempt(() =>
      collectLoginAttestations(
        attestors({ "http://node-1": new Error(`upstream said ${TOKEN}`), "http://node-2": refusal(401, "token-refused") }),
        endpoints(2),
        ATTEST_REQUEST,
        2,
      ),
    );
    await attempt(() =>
      oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: () => new Uint8Array(3) }).authorize({
        secretId: 1n,
        subset: [1],
        recipientIndex: 1,
        blockHash: new Uint8Array(32),
      }),
    );
    expect(raised).toHaveLength(7);
    for (const e of raised) {
      const err = e as Error & { faults?: unknown };
      expect(`${err.message} ${String(err)} ${JSON.stringify(err.faults ?? [])}`).not.toContain(TOKEN);
      expect(err.message).not.toContain(TOKEN.split(".")[1]!);
    }
  });

  it("nor an oidc signer's own rendering", () => {
    const signer = oidcSigner({ appId: APP_ID, idToken: TOKEN, requester: REQUESTER, sign: fakeSign() });
    expect(`${String(signer)} ${JSON.stringify(signer)}`).not.toContain(TOKEN);
  });

  it("keeps ApiKey usable as the session key", async () => {
    const session = new ApiKey("0x" + "07".repeat(32));
    const token = tokenFor(session.accountId);
    const signer = oidcSigner({ appId: APP_ID, idToken: token, requester: session.accountId, sign: (m) => session.sign(m) });
    const auth = await signer.authorize({ secretId: 1n, subset: [1], recipientIndex: 1, blockHash: new Uint8Array(32) });
    expect(auth.signature).toMatch(/^0x01[0-9a-f]{128}$/);
    session.free();
  });
});
