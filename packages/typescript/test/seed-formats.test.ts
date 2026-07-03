// Seed-format conformance: users load MatterVault API keys with
// @polkadot/keyring's `addFromUri`, as either a 0x-hex mini-secret or a BIP39
// mnemonic. Replay the Rust-emitted fixture (testvectors/seed_formats.json) to
// pin that the companion library derives the same account from both encodings —
// the exact dashboard↔SDK key-ingestion contract.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { u8aToHex } from "@polkadot/util";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const { cases } = JSON.parse(readFileSync(resolve(vectorsDir, "seed_formats.json"), "utf8"));

describe("seed format conformance", () => {
  beforeAll(async () => {
    await cryptoWaitReady();
  });

  it.each(cases)("both encodings derive account $account_id_hex", (c: any) => {
    const keyring = new Keyring({ type: "sr25519" });
    const fromMnemonic = keyring.addFromUri(c.mnemonic);
    const fromHex = keyring.addFromUri(`0x${c.mini_secret_hex}`);
    expect(u8aToHex(fromMnemonic.publicKey)).toBe(`0x${c.account_id_hex}`);
    expect(u8aToHex(fromHex.publicKey)).toBe(`0x${c.account_id_hex}`);
  });
});
