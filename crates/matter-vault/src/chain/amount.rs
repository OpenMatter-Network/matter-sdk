//! Token amounts, in plancks.
//!
//! Every amount in the public API is an integer count of the chain's smallest
//! unit — a `u128` plancks value. There is no `f64` anywhere: a float cannot
//! represent 18 decimal places, and rounding someone's balance is not a class of
//! bug worth risking for ergonomics.
//!
//! Conversion is explicit and takes the decimal count, because the correct
//! number is a property of the live runtime rather than a constant — see
//! [`super::ChainProperties`].

use crate::error::{Result, SdkError};

/// The largest decimal exponent a `u128` can hold (`10^38 < u128::MAX`).
const MAX_DECIMALS: u8 = 38;

/// Parse a decimal token amount into plancks.
///
/// Accepts `"1"`, `"1.5"`, `"0.000000000000000001"`, and a leading `+`. Rejects
/// more fractional digits than the chain supports rather than truncating —
/// silent truncation is how people lose money.
///
/// ```
/// # use matter_vault::chain::parse_amount;
/// assert_eq!(parse_amount("1", 12).unwrap(), 1_000_000_000_000);
/// assert_eq!(parse_amount("1.5", 12).unwrap(), 1_500_000_000_000);
/// assert_eq!(parse_amount("0.001", 3).unwrap(), 1);
/// // One digit too many for a 3-decimal chain: an error, not a rounded value.
/// assert!(parse_amount("0.0001", 3).is_err());
/// ```
pub fn parse_amount(text: &str, decimals: u8) -> Result<u128> {
    if decimals > MAX_DECIMALS {
        return Err(bad_amount(
            "chain reports more decimals than a u128 can hold",
        ));
    }

    let text = text.trim();
    let body = text.strip_prefix('+').unwrap_or(text);
    if body.is_empty() {
        return Err(bad_amount("amount is empty"));
    }
    if body.starts_with('-') {
        return Err(bad_amount("amount must not be negative"));
    }

    let (whole, fraction) = match body.split_once('.') {
        Some((w, f)) => (w, f),
        None => (body, ""),
    };
    // `"1."` and `".5"` are accepted by some parsers and mean different things to
    // different readers; require digits on both sides of a decimal point.
    if whole.is_empty() || (body.contains('.') && fraction.is_empty()) {
        return Err(bad_amount(
            "amount needs digits on both sides of the decimal point",
        ));
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad_amount(
            "amount must be decimal digits with at most one point",
        ));
    }
    if fraction.len() > decimals as usize {
        return Err(bad_amount(
            "amount has more fractional digits than this chain's decimals",
        ));
    }

    // Right-pad the fraction to exactly `decimals` digits, then read the whole
    // thing as one integer. No floating point at any step.
    let mut digits = String::with_capacity(whole.len() + decimals as usize);
    digits.push_str(whole);
    digits.push_str(fraction);
    for _ in fraction.len()..decimals as usize {
        digits.push('0');
    }
    digits.trim_start_matches('0').parse::<u128>().or_else(|e| {
        match digits.bytes().all(|b| b == b'0') {
            true => Ok(0),
            false => Err(bad_amount_from(e)),
        }
    })
}

/// Render plancks as a decimal string, with no trailing zeros in the fraction.
///
/// Lossless: `parse_amount(&format_amount(v, d), d) == Ok(v)` for every `v`.
///
/// ```
/// # use matter_vault::chain::format_amount;
/// assert_eq!(format_amount(1_500_000_000_000, 12), "1.5");
/// assert_eq!(format_amount(1_000_000_000_000, 12), "1");
/// // One planck at 12 decimals: twelve fractional digits, not fifteen.
/// assert_eq!(format_amount(1, 12), "0.000000000001");
/// assert_eq!(format_amount(0, 12), "0");
/// ```
pub fn format_amount(plancks: u128, decimals: u8) -> String {
    if decimals == 0 {
        return plancks.to_string();
    }
    let digits = format!("{plancks:0>width$}", width = decimals as usize + 1);
    let split = digits.len() - decimals as usize;
    let (whole, fraction) = digits.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    }
}

/// One whole token in plancks, i.e. `10^decimals`.
pub fn one_token(decimals: u8) -> u128 {
    10u128.pow(decimals as u32)
}

fn bad_amount(detail: &'static str) -> SdkError {
    SdkError::BadAmount {
        detail: detail.to_string(),
    }
}

fn bad_amount_from(e: core::num::ParseIntError) -> SdkError {
    SdkError::BadAmount {
        detail: format!("amount does not fit in u128 ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_losslessly_at_every_decimal_count() {
        // The property that matters: rendering then re-parsing must be identity,
        // or a UI that displays a balance and submits it back changes it.
        for decimals in [0u8, 3, 10, 12, 18] {
            for plancks in [
                0u128,
                1,
                999,
                1_000,
                10u128.pow(decimals as u32),
                u64::MAX as u128,
            ] {
                let text = format_amount(plancks, decimals);
                assert_eq!(
                    parse_amount(&text, decimals).unwrap(),
                    plancks,
                    "decimals={decimals} plancks={plancks} text={text}"
                );
            }
        }
    }

    #[test]
    fn parses_the_documented_forms() {
        assert_eq!(parse_amount("1", 12).unwrap(), 1_000_000_000_000);
        assert_eq!(parse_amount("1.5", 12).unwrap(), 1_500_000_000_000);
        assert_eq!(parse_amount("  +2.25  ", 4).unwrap(), 22_500);
        assert_eq!(parse_amount("0", 18).unwrap(), 0);
        assert_eq!(parse_amount("0.0", 18).unwrap(), 0);
        assert_eq!(parse_amount("12", 0).unwrap(), 12);
    }

    #[test]
    fn rejects_rather_than_truncates_excess_precision() {
        // The whole reason this is not a `f64::round`.
        assert!(parse_amount("0.0001", 3).is_err());
        assert!(parse_amount("1.0000000000001", 12).is_err());
        // Exactly at the limit is fine.
        assert_eq!(parse_amount("0.001", 3).unwrap(), 1);
    }

    #[test]
    fn rejects_malformed_and_negative_amounts() {
        for bad in [
            "", "  ", "-1", "-0.5", "abc", "1.2.3", "1,5", "1.", ".5", "0x10", "1e9",
        ] {
            assert!(parse_amount(bad, 12).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn one_token_matches_a_parsed_unit() {
        for decimals in [0u8, 3, 12, 18] {
            assert_eq!(one_token(decimals), parse_amount("1", decimals).unwrap());
        }
    }

    #[test]
    fn the_decimals_discrepancy_is_a_scale_factor_of_a_million() {
        // matter-node changed UNIT from 10^12 to 10^18 with no storage migration,
        // so the same plancks value means very different amounts depending on
        // which runtime is live. This is why nothing hardcodes the exponent.
        let plancks = 1_000_000_000_000_000_u128;
        assert_eq!(format_amount(plancks, 18), "0.001");
        assert_eq!(format_amount(plancks, 12), "1000");
    }
}
