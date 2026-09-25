// Every public amount is a `bigint` count of plancks; never a `number`, which
// cannot represent 18 decimal places. Conversions take the decimal count
// explicitly because it comes from the live runtime (see ChainProperties).

/** Thrown when an amount string cannot be converted to plancks. */
export class AmountError extends Error {
  constructor(detail: string) {
    super(`invalid amount: ${detail}`);
    this.name = "AmountError";
  }
}

/**
 * Parse a decimal token amount into plancks.
 *
 * Accepts `"1"`, `"1.5"` and a leading `+`. Throws `AmountError` on more
 * fractional digits than `decimals` rather than truncating.
 *
 * @example
 * parseAmount("1.5", 12)   // 1500000000000n
 * parseAmount("0.0001", 3) // throws: one digit too many for a 3-decimal chain
 */
export function parseAmount(text: string, decimals: number): bigint {
  const body = text.trim().replace(/^\+/, "");
  if (body === "") throw new AmountError("amount is empty");
  if (body.startsWith("-")) throw new AmountError("amount must not be negative");

  const pointAt = body.indexOf(".");
  const whole = pointAt === -1 ? body : body.slice(0, pointAt);
  const fraction = pointAt === -1 ? "" : body.slice(pointAt + 1);

  // Reject "1." and ".5": digits are required on both sides of a point.
  if (!/^[0-9]+$/.test(whole) || (pointAt !== -1 && !/^[0-9]+$/.test(fraction))) {
    throw new AmountError("amount must be decimal digits with at most one point");
  }
  if (fraction.length > decimals) {
    throw new AmountError("amount has more fractional digits than this chain's decimals");
  }

  return BigInt(whole + fraction.padEnd(decimals, "0"));
}

/**
 * Render plancks as a decimal string without trailing fractional zeros.
 * Lossless: `parseAmount(formatAmount(v, d), d) === v`.
 *
 * @example
 * formatAmount(1500000000000n, 12) // "1.5"
 * formatAmount(1n, 12)             // "0.000000000001"
 */
export function formatAmount(plancks: bigint, decimals: number): string {
  if (decimals === 0) return plancks.toString();
  const digits = plancks.toString().padStart(decimals + 1, "0");
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/, "");
  return fraction === "" ? whole : `${whole}.${fraction}`;
}

/** One whole token in plancks, i.e. `10 ** decimals`. */
export function oneToken(decimals: number): bigint {
  return 10n ** BigInt(decimals);
}

/**
 * Recover the decimal count from `ED === 10 ** (d - 3)`; `undefined` when `ed`
 * is not a positive power of ten.
 */
export function decimalsFromExistentialDeposit(ed: bigint): number | undefined {
  if (ed <= 0n) return undefined;
  let value = ed;
  let exponent = 0;
  while (value > 1n && value % 10n === 0n) {
    value /= 10n;
    exponent += 1;
  }
  return value === 1n ? exponent + 3 : undefined;
}
