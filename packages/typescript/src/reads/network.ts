// Network reads: which chain this is, its blocks, its timing, and the health of
// the node answering.

import { toHex } from "@openmatter-network/matter-sdk-core";

import { ClientError } from "../errors.js";
import type { ChainProperties } from "../network.js";
import { bytesFromHex } from "./leaf.js";
import { decodeStrict } from "./scale.js";
import { targetOf, type ConstantEntry, type StorageEntry, type StorageRequest } from "./source.js";

export const GET_HEADER = "chain_getHeader";
export const GET_BLOCK_HASH = "chain_getBlockHash";
export const GET_RUNTIME_VERSION = "state_getRuntimeVersion";
export const SYSTEM_NAME = "system_name";
export const SYSTEM_VERSION = "system_version";
export const SYSTEM_HEALTH = "system_health";

const NOW: StorageEntry = { pallet: "Timestamp", entry: "Now" };

const BLOCK_TIME: ConstantEntry = { pallet: "Babe", name: "ExpectedBlockTime" };
const SESSION_BLOCKS: ConstantEntry = { pallet: "Babe", name: "EpochDuration" };
const SESSIONS_PER_ERA: ConstantEntry = { pallet: "Staking", name: "SessionsPerEra" };
const BONDING_DURATION: ConstantEntry = { pallet: "Staking", name: "BondingDuration" };

/** The constants a timing read needs, in the order `decodeTiming` takes them. */
export const TIMING_CONSTANTS: readonly ConstantEntry[] = [
  BLOCK_TIME,
  SESSION_BLOCKS,
  SESSIONS_PER_ERA,
  BONDING_DURATION,
];

const HASH_BYTES = 32;
const HEX_NUMBER = /^0x[0-9a-fA-F]+$/;
const U64_MAX = (1n << 64n) - 1n;

/** Which chain this client is connected to, as read once at connect. */
export interface NetworkInfo {
  /** The chain's name, e.g. `MatterChain Testnet`. */
  readonly chainName: string;
  /** Block 0's hash: what tells one chain from another. */
  readonly genesisHash: string;
  /** The runtime's version at connect. */
  readonly specVersion: number;
  /** The token's symbol, e.g. `MTR`. */
  readonly tokenSymbol: string;
  /**
   * Decimal places in one token: divide plancks by ten to this power.
   * Consensus-backed, from the runtime rather than the node's chain spec.
   */
  readonly tokenDecimals: number;
  /** The prefix addresses on this chain are rendered under. */
  readonly ss58Prefix: number;
  /** The smallest balance an account may hold and stay alive, in plancks. */
  readonly existentialDeposit: bigint;
}

/** A block's place in the chain. */
export interface BlockHeader {
  /** The block's height. */
  readonly number: bigint;
  /** The block's hash: pass it to a façade's `at` to read at this block. */
  readonly hash: string;
  /** The hash of the block before it. */
  readonly parentHash: string;
}

/** A block and what its state says about itself. */
export interface Block extends BlockHeader {
  /**
   * When the block was authored, in milliseconds since the Unix epoch.
   * `undefined` for a block that records no time (the genesis block).
   */
  readonly timestampMs: bigint | undefined;
  /** The runtime version that executed the block. */
  readonly specVersion: number;
}

/** The node answering this client, and how far it has got. */
export interface NodeStatus {
  /** The node software's name. */
  readonly name: string;
  /** The node software's version. */
  readonly version: string;
  /** How many peers the node is connected to. */
  readonly peers: number;
  /** Whether the node is still catching up with the chain. */
  readonly isSyncing: boolean;
  /** Whether the node expects peers at all (a single dev node does not). */
  readonly shouldHavePeers: boolean;
  /** The newest block the node knows. It can still be reverted. */
  readonly bestNumber: bigint;
  /** That block's hash. */
  readonly bestHash: string;
  /** The newest block that can no longer be reverted. */
  readonly finalizedNumber: bigint;
  /** That block's hash. */
  readonly finalizedHash: string;
}

/**
 * How the chain measures time. Blocks and eras are the chain's own units; the
 * SDK does not turn them into wall-clock estimates for you.
 */
export interface NetworkTiming {
  /** The target time between blocks, in milliseconds. */
  readonly blockTimeMs: bigint;
  /** Blocks in one session. */
  readonly sessionBlocks: bigint;
  /** Sessions in one era. */
  readonly sessionsPerEra: number;
  /** Blocks in one era: `sessionBlocks * sessionsPerEra`. */
  readonly eraBlocks: bigint;
  /** Eras unbonded funds stay locked before they can be withdrawn. */
  readonly bondingDurationEras: number;
}

function field(target: string, answer: unknown, name: string, type: "string" | "number" | "boolean"): unknown {
  const value = typeof answer === "object" && answer !== null ? (answer as Record<string, unknown>)[name] : undefined;
  if (typeof value !== type) {
    throw ClientError.chain(target, `the node's answer has no ${type} ${name}`);
  }
  return value;
}

/** A 32-byte hash from the hex a node answers with, as lowercase `0x` hex. */
export function hashFromHex(target: string, text: unknown): string {
  const bytes = typeof text === "string" ? bytesFromHex(text) : undefined;
  if (bytes === undefined || bytes.length !== HASH_BYTES) {
    throw ClientError.chain(target, "the node did not answer with a block hash");
  }
  return toHex(bytes);
}

/** A block number as `chain_getBlockHash` takes it: hex, so no width is lost. */
export function blockNumberParam(number: bigint): string {
  return `0x${number.toString(16)}`;
}

/** The chain's identity, from what the client read at connect. */
export function networkInfo(properties: ChainProperties): NetworkInfo {
  return {
    chainName: properties.chainName,
    genesisHash: properties.genesisHash,
    specVersion: properties.specVersion,
    tokenSymbol: properties.tokenSymbol,
    tokenDecimals: properties.tokenDecimalsEffective,
    ss58Prefix: properties.ss58Prefix,
    existentialDeposit: properties.existentialDeposit,
  };
}

/** A header the node holds for `hash`, or the error for one it does not. */
export function decodeHeader(hash: Uint8Array, header: unknown): BlockHeader {
  if (header === null || header === undefined) {
    throw ClientError.chain(GET_HEADER, "the node does not have this block");
  }
  const number = field(GET_HEADER, header, "number", "string") as string;
  if (!HEX_NUMBER.test(number)) {
    throw ClientError.chain(GET_HEADER, "the header's block number is not hex");
  }
  return {
    number: BigInt(number),
    hash: toHex(hash),
    parentHash: hashFromHex(GET_HEADER, field(GET_HEADER, header, "parentHash", "string")),
  };
}

/** The one storage value a block read needs. */
export function nowRequest(): StorageRequest[] {
  return [{ entry: NOW, keys: [] }];
}

/**
 * `Timestamp.Now` is declared 128 bits wide; milliseconds fit 64 with room for
 * half a billion years, so anything wider is not a timestamp.
 */
function narrowMs(target: string, wide: bigint): bigint {
  if (wide > U64_MAX) throw ClientError.chain(target, `${wide} ms does not fit 64 bits`);
  return wide;
}

/** Build a block from its header and what its state holds. Pure. */
export function decodeBlock(
  header: BlockHeader,
  now: Uint8Array | undefined,
  version: unknown,
): Block {
  const target = targetOf(NOW);
  const timestampMs =
    now === undefined ? undefined : narrowMs(target, decodeStrict(target, now, (r) => r.u128()));
  return {
    number: header.number,
    hash: header.hash,
    parentHash: header.parentHash,
    timestampMs,
    specVersion: field(GET_RUNTIME_VERSION, version, "specVersion", "number") as number,
  };
}

/** Build the node's status from its own answers and the two headers. Pure. */
export function nodeStatus(
  name: unknown,
  version: unknown,
  health: unknown,
  best: BlockHeader,
  finalized: BlockHeader,
): NodeStatus {
  if (typeof name !== "string") throw ClientError.chain(SYSTEM_NAME, "the node did not answer with text");
  if (typeof version !== "string") {
    throw ClientError.chain(SYSTEM_VERSION, "the node did not answer with text");
  }
  return {
    name,
    version,
    peers: field(SYSTEM_HEALTH, health, "peers", "number") as number,
    isSyncing: field(SYSTEM_HEALTH, health, "isSyncing", "boolean") as boolean,
    shouldHavePeers: field(SYSTEM_HEALTH, health, "shouldHavePeers", "boolean") as boolean,
    bestNumber: best.number,
    bestHash: best.hash,
    finalizedNumber: finalized.number,
    finalizedHash: finalized.hash,
  };
}

/** Build the chain's timing from its constants' bytes, in `TIMING_CONSTANTS` order. Pure. */
export function decodeTiming(constants: readonly Uint8Array[]): NetworkTiming {
  const [blockTime, sessionBlocks, sessionsPerEra, bondingDuration] = constants as [
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
  ];
  const blocks = decodeStrict(`${SESSION_BLOCKS.pallet}.${SESSION_BLOCKS.name}`, sessionBlocks, (r) => r.u64());
  const sessions = decodeStrict(
    `${SESSIONS_PER_ERA.pallet}.${SESSIONS_PER_ERA.name}`,
    sessionsPerEra,
    (r) => r.u32(),
  );
  const blockTimeTarget = `${BLOCK_TIME.pallet}.${BLOCK_TIME.name}`;
  const era = blocks * BigInt(sessions);
  return {
    blockTimeMs: narrowMs(blockTimeTarget, decodeStrict(blockTimeTarget, blockTime, (r) => r.u128())),
    sessionBlocks: blocks,
    sessionsPerEra: sessions,
    eraBlocks: era > U64_MAX ? U64_MAX : era,
    bondingDurationEras: decodeStrict(
      `${BONDING_DURATION.pallet}.${BONDING_DURATION.name}`,
      bondingDuration,
      (r) => r.u32(),
    ),
  };
}
