// Token amounts, in plancks.
//
// Every amount in the public API is a `bigint` count of the chain's smallest
// unit. There is no `number` anywhere: a double cannot represent 18 decimal
// places, and rounding someone's balance is not a class of bug worth risking for
// ergonomics.
//
// Conversion is explicit and takes the decimal count, because the correct number
// is a property of the live runtime rather than a constant — see ChainProperties.

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
 * Accepts `"1"`, `"1.5"`, `"0.000000000000000001"`, and a leading `+`. Rejects
 * more fractional digits than the chain supports rather than truncating —
 * silent truncation is how people lose money.
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

  // "1." and ".5" are read differently by different people; require digits on
  // both sides of a point.
  if (!/^[0-9]+$/.test(whole) || (pointAt !== -1 && !/^[0-9]+$/.test(fraction))) {
    throw new AmountError("amount must be decimal digits with at most one point");
  }
  if (fraction.length > decimals) {
    throw new AmountError("amount has more fractional digits than this chain's decimals");
  }

  // Right-pad the fraction to exactly `decimals` digits and read the whole thing
  // as one integer. No floating point at any step.
  return BigInt(whole + fraction.padEnd(decimals, "0"));
}

/**
 * Render plancks as a decimal string, with no trailing zeros in the fraction.
 *
 * Lossless: `parseAmount(formatAmount(v, d), d) === v` for every `v`.
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
 * Recover the decimal count from `ED === 10 ** (d - 3)`.
 *
 * `undefined` when the constant is not a clean power of ten, meaning the runtime
 * changed its existential-deposit policy — better to fall back than to report a
 * confidently wrong exponent.
 */
export function decimalsFromExistentialDeposit(ed: bigint): number | undefined {
  if (ed <= 0n) return undefined;
  let value = ed;
  let exponent = 0;
  while (value > 1n && value % 10n === 0n) {
    value /= 10n;
    exponent += 1;
  }
  // `Balances.ExistentialDeposit` is UNIT / 1000.
  return value === 1n ? exponent + 3 : undefined;
}
