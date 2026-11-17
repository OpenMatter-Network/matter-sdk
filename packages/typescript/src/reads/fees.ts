// Fee reads: what a call would cost, and who would be charged for it.

import { toHex } from "@openmatter-network/matter-sdk-core";

import { ClientError } from "../errors.js";
import { concatBytes, decodeStrict, encodeBytes, encodeU128, encodeU32 } from "./scale.js";

export const QUERY_CALL_INFO = "TransactionPaymentCallApi_query_call_info";
export const FEE_PAYER = "PaymasterApi_fee_payer";

/**
 * What signing adds around a call: the length prefix, version byte, signer
 * address, signature, and the signed extensions' bytes. An upper bound for an
 * sr25519 signature on a mortal extrinsic with no tip, so an estimate never
 * undercounts the length fee.
 */
export const EXTRINSIC_OVERHEAD_BYTES = 112;

/** An estimate assumes no tip: the SDK never adds one. */
const NO_TIP = 0n;
const U32_MAX = 0xffff_ffff;
const ACCOUNT_BYTES = 32;
const ORG_BYTES = 32;

/** How the runtime schedules a call. */
export enum DispatchClass {
  /** An ordinary call. */
  Normal = "Normal",
  /** An operational call, which has space reserved in every block. */
  Operational = "Operational",
  /** A call the block cannot be built without. */
  Mandatory = "Mandatory",
}

/** `frame_support::dispatch::DispatchClass`, by enum index. */
export const DISPATCH_CLASSES: readonly DispatchClass[] = [
  DispatchClass.Normal,
  DispatchClass.Operational,
  DispatchClass.Mandatory,
];

/** The computation a call is allowed. */
export interface Weight {
  /** Execution time, in picoseconds on reference hardware. */
  readonly refTime: bigint;
  /** Bytes of state proof the call may need. */
  readonly proofSize: bigint;
}

/** The organization a fee is booked against, and for which member. */
export interface BilledTo {
  /** The organization whose treasury pays, as `0x` hex. */
  readonly org: string;
  /** The member the spend counts against. */
  readonly member: string;
}

/** What a call would cost, and who would be charged for it. */
export interface FeeEstimate {
  /** The pallet of the call priced. */
  readonly pallet: string;
  /** The call priced. */
  readonly call: string;
  /**
   * The fee the chain would charge, in plancks, with no tip. Governance fee
   * overrides are already applied.
   */
  readonly partialFee: bigint;
  /** The computation the call is allowed. */
  readonly weight: Weight;
  /** How the runtime schedules the call. */
  readonly dispatchClass: DispatchClass;
  /**
   * The extrinsic length the fee was computed for: the encoded call plus an
   * upper bound on what signing adds.
   */
  readonly encodedLen: number;
  /**
   * Whether the call was priced as this client would submit it for a member:
   * wrapped in `Proxy.proxy`.
   */
  readonly wrappedInProxy: boolean;
  /** The account that would sign: this client's. `undefined` for a read-only client. */
  readonly signer: string | undefined;
  /**
   * The account the fee would be taken from. `undefined` when the runtime
   * cannot say: the client has no signer, or the call is one whose sponsorship
   * the runtime does not answer for. Never read it as "the signer pays".
   */
  readonly payer: string | undefined;
  /** The organization the fee is booked against, when one pays. */
  readonly billedTo: BilledTo | undefined;
}

/** The fee, weight and dispatch class from `query_call_info`'s answer. */
export interface DispatchInfo {
  readonly partialFee: bigint;
  readonly weight: Weight;
  readonly dispatchClass: DispatchClass;
}

/**
 * The length the fee is computed for, and `query_call_info`'s arguments: the
 * call as the runtime decodes it, then that length.
 */
export function callInfoArgs(call: Uint8Array): { encodedLen: number; args: Uint8Array } {
  const encodedLen = call.length + EXTRINSIC_OVERHEAD_BYTES;
  if (encodedLen > U32_MAX) {
    throw ClientError.chain(QUERY_CALL_INFO, "the call is too long to be an extrinsic");
  }
  return { encodedLen, args: concatBytes(call, encodeU32(encodedLen)) };
}

/** `fee_payer`'s arguments: who signs, the call as bytes, the fee and the tip. */
export function feePayerArgs(signer: Uint8Array, call: Uint8Array, fee: bigint): Uint8Array {
  return concatBytes(signer, encodeBytes(call), encodeU128(fee), encodeU128(NO_TIP));
}

/** The fee and weight from `query_call_info`'s answer. Pure. */
export function decodeDispatchInfo(raw: Uint8Array): DispatchInfo {
  return decodeStrict(QUERY_CALL_INFO, raw, (reader) => {
    const refTime = reader.compactU64();
    const proofSize = reader.compactU64();
    const index = reader.u8();
    const dispatchClass = DISPATCH_CLASSES[index];
    if (dispatchClass === undefined) {
      throw ClientError.chain(
        QUERY_CALL_INFO,
        `dispatch class ${index} is not a variant this SDK knows`,
      );
    }
    return { partialFee: reader.u128(), weight: { refTime, proofSize }, dispatchClass };
  });
}

/** What the client knows about the call before asking the chain. */
export interface Priced {
  readonly pallet: string;
  readonly call: string;
  readonly encodedLen: number;
  readonly wrappedInProxy: boolean;
  readonly signer: string | undefined;
}

/**
 * Build the estimate from what was priced and the runtime's two answers. `payer`
 * is `fee_payer`'s raw answer, absent when there was no signer to ask about.
 * Pure.
 */
export function decodeEstimate(
  priced: Priced,
  info: DispatchInfo,
  payer: Uint8Array | undefined,
  address: (accountId: Uint8Array) => string,
): FeeEstimate {
  const answer =
    payer === undefined
      ? undefined
      : decodeStrict(FEE_PAYER, payer, (reader) =>
          reader.option((some) => ({
            account: some.fixed(ACCOUNT_BYTES),
            booked: some.option((booked) => ({
              org: booked.fixed(ORG_BYTES),
              member: booked.fixed(ACCOUNT_BYTES),
            })),
          })),
        );
  return {
    pallet: priced.pallet,
    call: priced.call,
    partialFee: info.partialFee,
    weight: info.weight,
    dispatchClass: info.dispatchClass,
    encodedLen: priced.encodedLen,
    wrappedInProxy: priced.wrappedInProxy,
    signer: priced.signer,
    payer: answer === undefined ? undefined : address(answer.account),
    billedTo:
      answer?.booked === undefined
        ? undefined
        : { org: toHex(answer.booked.org), member: address(answer.booked.member) },
  };
}
