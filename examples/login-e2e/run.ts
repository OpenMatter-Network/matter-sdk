// OpenMatter Login end to end against a LOCAL chain, committee and sign-in
// issuer: register a new login, then sign in again from a fresh session and
// recover the same key. Refuses any chain that is not a local dev chain.
//
// Everything login-specific is the SDK's (`packages/typescript-core`); @polkadot
// only submits extrinsics and makes `state_call`s. See README.md.

import { ApiPromise, Keyring, WsProvider } from "@polkadot/api";
import type { KeyringPair } from "@polkadot/keyring/types";
import type { SubmittableExtrinsic } from "@polkadot/api/types";
import { u8aConcat, u8aToHex } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";

import {
  ApiKey,
  attestLoginRequest,
  collectLoginAttestations,
  decodeIdTokenClaims,
  decodeLoginRecord,
  DecryptError,
  FetchTransport,
  LOGIN_FOR_RUNTIME_API,
  loginAccount,
  LoginError,
  loginForArgs,
  loginIdentity,
  loginNonce,
  oidcSigner,
  openLogin,
  prepareLoginRegistration,
  registerLogin,
  toHex,
  wipe,
  type CommitteeNode,
  type LoginRecord,
  type LoginSession,
} from "../../packages/typescript-core/src/index.js";
import { startIssuer, type LocalIssuer } from "./issuer.js";

const RPC_URL = process.env.MATTER_RPC_URL ?? "ws://127.0.0.1:9944";
const LOCAL_RPC = /^wss?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\/?$/;
/** The sudo key of a dev chain. Public knowledge: this harness is local-only. */
const SUDO_URI = "//Alice";
const AUDIENCE = "login-e2e-client";
const APP_QUOTA = 10;
const PLANCK_PER_MTR = 10n ** 18n;
/** Registration is paid by the new account until fee sponsorship lands. */
const FUNDING = 50n * PLANCK_PER_MTR;

const STATE_CALL_TYPES = {
  KgcNodeInfoJs: { endpoint: "Bytes", dkg_index: "u64" },
  EncryptedSecretJs: { binding_id: "Bytes", capsule: "Bytes", proof: "Bytes", ct: "Bytes" },
};

const step = (name: string, detail = "") => console.log(`${name}${detail ? `: ${detail}` : ""}`);

function describeDispatchError(api: ApiPromise, err: any): string {
  if (err?.isModule) {
    const meta = api.registry.findMetaError(err.asModule);
    return `${meta.section}.${meta.name}`;
  }
  return String(err);
}

/** Submit and wait for FINALITY: the committee reads finalized state. */
function submit(api: ApiPromise, tx: SubmittableExtrinsic<"promise">, pair: KeyringPair): Promise<any[]> {
  return new Promise((resolve, reject) => {
    tx.signAndSend(pair, { nonce: -1 }, ({ status, events, dispatchError }) => {
      if (dispatchError) reject(new Error(`dispatch failed: ${describeDispatchError(api, dispatchError)}`));
      else if (status.isFinalized) resolve(events);
    }).catch(reject);
  });
}

async function sudo(api: ApiPromise, alice: KeyringPair, call: SubmittableExtrinsic<"promise">): Promise<void> {
  const events = await submit(api, api.tx.sudo!.sudo!(call), alice);
  const done = events.find(({ event }) => api.events.sudo!.Sudid!.is(event));
  const result = done?.event.data[0];
  if (result?.isErr) throw new Error(`sudo call failed: ${describeDispatchError(api, result.asErr)}`);
}

async function stateCall(api: ApiPromise, name: string, argsHex = "0x"): Promise<Uint8Array> {
  return ((await api.rpc.state.call(name, argsHex)) as any).toU8a(true);
}

function optionBytes(api: ApiPromise, bytes: Uint8Array): Uint8Array | null {
  const opt = api.registry.createType("Option<Bytes>", bytes) as any;
  return opt.isSome ? opt.unwrap().toU8a(true) : null;
}

const u32Arg = (api: ApiPromise, n: number) => api.createType("u32", n).toU8a();

interface Committee {
  threshold: number;
  sharedA: Uint8Array;
  nodes: CommitteeNode[];
}

async function committeeAt(api: ApiPromise, epoch: number): Promise<Committee> {
  const rows = api.registry.createType(
    "Vec<(AccountId, KgcNodeInfoJs)>",
    await stateCall(api, "KgcApi_kgc_nodes"),
  ) as any[];
  const nodes = await Promise.all(
    rows.map(async ([account, info]): Promise<CommitteeNode> => {
      const commitment = optionBytes(
        api,
        await stateCall(api, "KgcApi_share_commitment", u8aToHex(u8aConcat(u32Arg(api, epoch), account.toU8a()))),
      );
      if (!commitment) throw new Error(`no share commitment for ${account} at epoch ${epoch}`);
      return {
        index: info.dkg_index.toNumber(),
        endpoint: new TextDecoder().decode(info.endpoint.toU8a(true)).trim().replace(/\/+$/, ""),
        shareCommitment: commitment,
      };
    }),
  );
  const sharedA = optionBytes(api, await stateCall(api, "KgcApi_shared_a"));
  if (!sharedA) throw new Error("KGC shared_a unavailable (DKG not finalised)");
  const params = api.registry.createType(
    "(u64,u64)",
    await stateCall(api, "KgcApi_threshold_params_at_epoch", u8aToHex(u32Arg(api, epoch))),
  ) as any;
  return { threshold: params[1].toNumber(), sharedA, nodes };
}

async function loginFor(api: ApiPromise, appId: Uint8Array, identity: Uint8Array): Promise<LoginRecord | null> {
  return decodeLoginRecord(await stateCall(api, LOGIN_FOR_RUNTIME_API, loginForArgs(appId, identity)));
}

/** A fresh session key and a token minted for it, as a browser would hold after a sign-in redirect. */
function newSession(issuer: LocalIssuer, subject: string): { session: LoginSession; done(): void } {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = new ApiKey(toHex(seed));
  wipe(seed);
  const idToken = issuer.mint({ aud: AUDIENCE, sub: subject, nonce: loginNonce(key.accountId) });
  return {
    session: { idToken, requester: key.accountId, sign: (payload) => key.sign(payload) },
    done: () => key.free(),
  };
}

async function main(): Promise<void> {
  if (!LOCAL_RPC.test(RPC_URL)) throw new Error(`refusing to run against ${RPC_URL}: this harness is local-only`);
  await cryptoWaitReady();
  const api = await ApiPromise.create({ provider: new WsProvider(RPC_URL), noInitWarn: true });
  const issuer = await startIssuer();
  try {
    api.registry.register(STATE_CALL_TYPES);
    const chain = (await api.rpc.system.chain()).toString();
    if (!/dev/i.test(chain)) throw new Error(`refusing to run on chain "${chain}": not a dev chain`);
    if (!api.tx.logins) throw new Error("this runtime has no Logins pallet");
    const genesis = api.genesisHash.toU8a();
    const keyring = new Keyring({ type: "sr25519" });
    const alice = keyring.addFromUri(SUDO_URI);
    step("chain", `${chain}, spec ${api.runtimeVersion.specVersion.toNumber()}; issuer ${issuer.iss}`);

    // ---- Operator setup: a new app that trusts this run's issuer -----------------
    const appId = crypto.getRandomValues(new Uint8Array(32));
    await sudo(api, alice, api.tx.logins.registerApp!(toHex(appId), APP_QUOTA));
    await sudo(api, alice, api.tx.logins.setIssuer!(toHex(appId), issuer.iss, [AUDIENCE], issuer.jwksUri));
    step("app registered", toHex(appId));

    const jointPk = optionBytes(api, await stateCall(api, "KgcApi_joint_pk"));
    if (!jointPk?.length) throw new Error("KGC DKG not finalised on chain (joint_pk is None)");
    const epoch = (api.registry.createType("u32", await stateCall(api, "KgcApi_dkg_epoch")) as any).toNumber();
    const committee = await committeeAt(api, epoch);
    step("committee", `epoch ${epoch}, ${committee.nodes.length} nodes, threshold ${committee.threshold}`);

    // ---- First sign-in: register ------------------------------------------------
    const subject = `user-${Date.now().toString(36)}`;
    const first = newSession(issuer, subject);
    const claims = decodeIdTokenClaims(first.session.idToken);

    const seed = crypto.getRandomValues(new Uint8Array(32));
    const account = loginAccount(seed);
    const pair = keyring.addFromSeed(seed);
    if (toHex(pair.publicKey) !== toHex(account)) throw new Error("the SDK and @polkadot derive different accounts");
    await submit(api, api.tx.balances.transferKeepAlive(pair.address, FUNDING), alice);

    const registration = prepareLoginRegistration({
      appId,
      issuer: claims.iss,
      subject: claims.sub,
      account,
      jointPk,
      epoch,
      seed,
      genesis,
    });
    if ((await loginFor(api, appId, registration.identity)) !== null) throw new Error("identity already registered");

    const transport = new FetchTransport();
    const attestRequest = await attestLoginRequest(registration, first.session);
    const attestations = await collectLoginAttestations(transport, committee.nodes, attestRequest, committee.threshold);
    step("attested", `${attestations.length} of ${committee.nodes.length} nodes`);

    const call = registerLogin(registration, attestations);
    await submit(
      api,
      api.tx.logins.registerLogin!(
        toHex(call.appId),
        toHex(call.identity),
        {
          bindingId: toHex(call.payload.bindingId),
          capsule: toHex(call.payload.capsule),
          proof: toHex(call.payload.proof),
          ct: toHex(call.payload.ct),
        },
        call.epoch,
        call.attestations.map(([node, signature]) => [toHex(node), toHex(signature)]),
      ),
      pair,
    );
    const expectedSeedHex = toHex(seed);
    wipe(seed);
    first.done();

    const record = await loginFor(api, appId, registration.identity);
    if (!record) throw new Error("register_login finalized but the chain has no login record");
    if (toHex(record.account) !== toHex(account)) throw new Error("the login record names another account");
    step("registered", `secret ${record.secretId}, generation ${record.generation}`);

    // ---- Every later sign-in: a NEW session key, a NEW token, nothing kept -------
    const later = newSession(issuer, subject);
    const laterClaims = decodeIdTokenClaims(later.session.idToken);
    const identity = loginIdentity(appId, laterClaims.iss, laterClaims.sub);
    const found = await loginFor(api, appId, identity);
    if (!found) throw new Error("no login for this identity");

    const secretIdArg = u8aToHex(api.createType("u128", found.secretId).toU8a());
    const stored = (
      api.registry.createType("Option<EncryptedSecretJs>", await stateCall(api, "SecretsApi_secret_payload", secretIdArg)) as any
    ).unwrap();
    const secretEpoch = (
      api.registry.createType("Option<u32>", await stateCall(api, "SecretsApi_secret_epoch", secretIdArg)) as any
    )
      .unwrap()
      .toNumber();
    const openWith = async (session: LoginSession) => {
      const at = await committeeAt(api, secretEpoch);
      return openLogin(transport, oidcSigner({ appId, ...session }), {
        appId,
        identity,
        account: found.account,
        secretId: found.secretId,
        epoch: secretEpoch,
        bindingId: stored.binding_id.toU8a(true),
        capsule: stored.capsule.toU8a(true),
        ct: stored.ct.toU8a(true),
        sharedA: at.sharedA,
        blockHash: (await api.rpc.chain.getFinalizedHead()).toU8a(),
        threshold: at.threshold,
        nodes: at.nodes,
      });
    };

    const recovered = await openWith(later.session);
    // Compared in process, never printed.
    const sameKey = toHex(recovered) === expectedSeedHex;
    wipe(recovered);
    later.done();
    if (!sameKey) throw new Error("MISMATCH: the recovered seed is not the registered one");
    step("signed in", "a fresh session recovered the registered key");

    // ---- What must be refused ----------------------------------------------------
    const again = newSession(issuer, subject);
    const second = await collectLoginAttestations(
      transport,
      committee.nodes,
      await attestLoginRequest(registration, again.session),
      committee.threshold,
    ).catch((e: unknown) => e);
    again.done();
    if (!(second instanceof LoginError) || second.kind !== "already-registered") {
      throw new Error(`a second registration was not refused as already-registered: ${String(second)}`);
    }
    step("refused", `second registration (${second.kind}, HTTP ${second.status})`);

    const stranger = newSession(issuer, `someone-else-${subject}`);
    const pried = await openWith(stranger.session).catch((e: unknown) => e);
    stranger.done();
    if (!(pried instanceof DecryptError) || pried.kind !== "quorum") {
      throw new Error("another subject's token was not refused by the committee");
    }
    step("refused", `another subject's token (${pried.faults[0]?.detail ?? pried.kind})`);

    console.log(`\nOpenMatter Login round trip verified ✔  (committee fetched the issuer's keys ${issuer.jwksHits()}×)`);
  } finally {
    await issuer.stop();
    await api.disconnect();
  }
}

main().catch((e) => {
  console.error(`\nFAILED: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
