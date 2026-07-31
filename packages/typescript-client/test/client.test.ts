// MatterClient behaviour that does not need a chain.
//
// The ChainBackend seam is narrow enough that a fake covers the parts which must
// never regress: the network guards, the amount arithmetic, and the read-only
// contract. Getting those wrong spends real money.

import { describe, expect, it, vi } from "vitest";

import {
  ApiKey,
  ChainProperties,
  ClientError,
  MatterClient,
  Network,
  TESTNET_GENESIS,
  decimalsDisagree,
  decimalsFromExistentialDeposit,
  detectMainnet,
  emitted,
  formatAmount,
  oneToken,
  parseAmount,
  type ChainBackend,
  type TxReceipt,
} from "../src/index.js";

const SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const MNEMONIC = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

function properties(overrides: Partial<ChainProperties> = {}): ChainProperties {
  const effective = overrides.tokenDecimalsEffective ?? 18;
  return {
    genesisHash: TESTNET_GENESIS,
    chainName: "MatterChain Testnet",
    specVersion: 308,
    tokenSymbol: "MTR-Test",
    ss58Prefix: 42,
    tokenDecimalsDeclared: 18,
    tokenDecimalsEffective: effective,
    existentialDeposit: 10n ** BigInt(effective - 3),
    ...overrides,
  };
}

class FakeBackend implements ChainBackend {
  submitted: Array<[string, string, unknown[]]> = [];
  disconnected = false;
  #properties: ChainProperties;
  #signs: boolean;
  #onSubmit?: () => Promise<TxReceipt>;

  constructor(props = properties(), signs = true, onSubmit?: () => Promise<TxReceipt>) {
    this.#properties = props;
    this.#signs = signs;
    this.#onSubmit = onSubmit;
  }

  async properties(): Promise<ChainProperties> {
    return this.#properties;
  }
  async submit(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    this.submitted.push([pallet, call, args]);
    if (this.#onSubmit) return this.#onSubmit();
    return {
      txHash: "0xtx",
      blockHash: "0xblock",
      events: [["Secrets", "SecretStored"] as const, ["System", "ExtrinsicSuccess"] as const],
    };
  }
  async query(pallet: string, entry: string, keys: unknown[]): Promise<unknown> {
    return { pallet, entry, keys };
  }
  async runtimeApi(method: string): Promise<string> {
    return `0x${method.length.toString(16)}`;
  }
  constant(pallet: string, name: string): unknown {
    return `${pallet}.${name}`;
  }
  canSign(): boolean {
    return this.#signs;
  }
  encodeAddress(accountId: Uint8Array): string {
    // The fake renders a recognisable stand-in; real SS58 needs the chain registry.
    return `ss58:${accountId.length}`;
  }
  async disconnect(): Promise<void> {
    this.disconnected = true;
  }
}

// --- amounts ---------------------------------------------------------------

describe("amounts", () => {
  it("round-trips losslessly at every decimal count", () => {
    // A UI that displays a balance and submits it back must not change it.
    for (const decimals of [0, 3, 12, 18]) {
      for (const plancks of [0n, 1n, 999n, 10n ** BigInt(decimals), 2n ** 64n]) {
        const text = formatAmount(plancks, decimals);
        expect(parseAmount(text, decimals)).toBe(plancks);
      }
    }
  });

  it("rejects excess precision rather than truncating", () => {
    expect(parseAmount("0.001", 3)).toBe(1n);
    expect(() => parseAmount("0.0001", 3)).toThrow(/fractional digits/);
  });

  it("rejects malformed and negative amounts", () => {
    for (const bad of ["", "  ", "-1", "abc", "1.2.3", "1,5", "1e9", "1.", ".5"]) {
      expect(() => parseAmount(bad, 12), bad).toThrow();
    }
  });

  it("treats the decimals discrepancy as a factor of a million", () => {
    // matter-node changed UNIT from 10^12 to 10^18 with no storage migration.
    expect(formatAmount(10n ** 15n, 18)).toBe("0.001");
    expect(formatAmount(10n ** 15n, 12)).toBe("1000");
  });

  it("derives decimals from the existential deposit", () => {
    expect(decimalsFromExistentialDeposit(10n ** 15n)).toBe(18);
    expect(decimalsFromExistentialDeposit(10n ** 9n)).toBe(12);
    // Not a clean power of ten: the ED policy changed, so fall back rather than
    // reporting a confidently wrong exponent.
    expect(decimalsFromExistentialDeposit(1500n)).toBeUndefined();
    expect(decimalsFromExistentialDeposit(0n)).toBeUndefined();
  });

  it("uses the effective decimals, not the declared ones", async () => {
    const client = await MatterClient.connect({
      backend: new FakeBackend(properties({ tokenDecimalsDeclared: 18, tokenDecimalsEffective: 12 })),
    });
    expect(client.oneToken()).toBe(10n ** 12n);
    expect(client.parseAmount("1")).toBe(10n ** 12n);
    expect(client.formatAmount(10n ** 12n)).toBe("1");
    expect(oneToken(12)).toBe(10n ** 12n);
  });
});

// --- the network guards ----------------------------------------------------

describe("network guards", () => {
  const unknownGenesis = `0x${"ab".repeat(32)}`;

  it("lets the pinned testnet genesis win over the token symbol", () => {
    const result = detectMainnet(properties({ tokenSymbol: "MTR" }));
    expect(result).toEqual({ isMainnet: false, detectedVia: "genesis-hash" });
  });

  it("falls back to the token symbol for an unknown chain", () => {
    expect(detectMainnet(properties({ tokenSymbol: "MTR", genesisHash: unknownGenesis }))).toEqual({
      isMainnet: true,
      detectedVia: "token-symbol",
    });
    expect(
      detectMainnet(properties({ tokenSymbol: "MTR-Test", genesisHash: unknownGenesis })),
    ).toEqual({ isMainnet: false, detectedVia: "token-symbol" });
  });

  it("rejects a testnet config pointed at mainnet", async () => {
    // A typo'd RPC URL must fail before it costs anything.
    const backend = new FakeBackend(
      properties({ tokenSymbol: "MTR", chainName: "MatterChain", genesisHash: unknownGenesis }),
    );
    await expect(
      MatterClient.connectWithApiKey(new ApiKey(SEED_HEX), { backend, network: Network.Testnet }),
    ).rejects.toMatchObject({ kind: "wrong-network" } satisfies Partial<ClientError>);
  });

  it("requires confirmation before a signing client touches mainnet", async () => {
    const mainnet = () =>
      new FakeBackend(
        properties({ tokenSymbol: "MTR", chainName: "MatterChain", genesisHash: unknownGenesis }),
      );

    await expect(
      MatterClient.connectWithApiKey(new ApiKey(SEED_HEX), {
        backend: mainnet(),
        network: Network.Mainnet,
      }),
    ).rejects.toMatchObject({ kind: "mainnet-not-confirmed" } satisfies Partial<ClientError>);

    // Explicit opt-in is accepted.
    const confirmed = await MatterClient.connectWithApiKey(new ApiKey(SEED_HEX), {
      backend: mainnet(),
      network: Network.Mainnet,
      confirmMainnet: true,
    });
    expect(confirmed.accountId).toBeDefined();
  });

  it("lets a read-only client reach mainnet without confirmation", async () => {
    // Reading cannot spend anything, so the guard does not apply.
    const client = await MatterClient.connect({
      backend: new FakeBackend(
        properties({ tokenSymbol: "MTR", chainName: "MatterChain", genesisHash: unknownGenesis }),
      ),
      network: Network.Mainnet,
    });
    expect(client.accountId).toBeUndefined();
  });

  it("warns once when the chain spec disagrees with the runtime", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const props = properties({ tokenDecimalsDeclared: 18, tokenDecimalsEffective: 12 });
    expect(decimalsDisagree(props)).toBe(true);

    await MatterClient.connect({ backend: new FakeBackend(props) });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toContain("ExistentialDeposit implies 12");
    warn.mockRestore();
  });
});

// --- the read-only contract ------------------------------------------------

describe("read-only clients", () => {
  it("refuse to submit, with a typed error", async () => {
    const client = await MatterClient.connect({ backend: new FakeBackend(properties(), false) });
    expect(client.accountId).toBeUndefined();
    expect(client.accountIdHex).toBeUndefined();
    await expect(client.tx("Staking", "chill", [])).rejects.toMatchObject({
      kind: "read-only",
    } satisfies Partial<ClientError>);
  });

  it("still read", async () => {
    const client = await MatterClient.connect({ backend: new FakeBackend() });
    expect(await client.query("System", "Account", ["addr"])).toMatchObject({ entry: "Account" });
    expect(await client.runtimeApi("KgcApi_dkg_epoch")).toMatch(/^0x/);
    expect(client.constant("Balances", "ExistentialDeposit")).toBe(
      "Balances.ExistentialDeposit",
    );
  });
});

// --- identity and the generic surface --------------------------------------

describe("signing clients", () => {
  it("report a consistent identity", async () => {
    const key = new ApiKey(SEED_HEX);
    const client = await MatterClient.connectWithApiKey(key, { backend: new FakeBackend() });
    expect(client.accountId).toEqual(key.accountId);
    expect(client.accountIdHex).toBe(key.accountIdHex);
    expect(client.signer).toBe(key);
  });

  it("accept a key string as well as an ApiKey", async () => {
    const client = await MatterClient.connectWithApiKey(MNEMONIC, { backend: new FakeBackend() });
    expect(client.accountIdHex).toBe(new ApiKey(MNEMONIC).accountIdHex);
  });

  it("forward tx to the backend and report events", async () => {
    const backend = new FakeBackend();
    const client = await MatterClient.connectWithApiKey(new ApiKey(SEED_HEX), { backend });

    const receipt = await client.tx("Jobs", "request_deployment", [{ sku: 1 }]);
    expect(backend.submitted[0]).toEqual(["Jobs", "request_deployment", [{ sku: 1 }]]);
    expect(emitted(receipt, "Secrets", "SecretStored")).toBe(true);
    expect(emitted(receipt, "Secrets", "SecretDeleted")).toBe(false);
  });

  it("time out rather than hang when finalization never arrives", async () => {
    // A submitted extrinsic that never finalizes must surface as a typed timeout
    // that says it may still land — resubmitting blindly could apply it twice.
    const backend = new FakeBackend(properties(), true, () => new Promise<TxReceipt>(() => {}));
    const client = await MatterClient.connectWithApiKey(new ApiKey(SEED_HEX), {
      backend,
      finalityTimeoutMs: 20,
    });
    await expect(client.tx("Staking", "chill", [])).rejects.toMatchObject({
      kind: "finality-timeout",
    } satisfies Partial<ClientError>);
  });

  it("disconnect through the backend", async () => {
    const backend = new FakeBackend();
    const client = await MatterClient.connect({ backend });
    await client.disconnect();
    expect(backend.disconnected).toBe(true);
  });
});

describe("configuration", () => {
  it("requires an explicit url for a custom network", async () => {
    await expect(MatterClient.connect({ network: Network.Custom })).rejects.toMatchObject({
      kind: "config",
    } satisfies Partial<ClientError>);
  });

  it("re-exports the light package surface", async () => {
    // One import for chain consumers: ApiKey comes from matter-vault via the
    // barrel, not from a second package name.
    const { Aad, encrypt } = await import("../src/index.js");
    expect(Aad.EnvV1).toBeDefined();
    expect(typeof encrypt).toBe("function");
  });
});
