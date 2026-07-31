package mattervault

// Token amounts, in plancks.
//
// Every amount in the public API is a *big.Int count of the chain's smallest unit.
// There is no float anywhere: a float64 cannot represent 18 decimal places, and
// rounding someone's balance is not a class of bug worth risking for ergonomics.
// A uint64 is not enough either — 10^18 plancks of a modest balance overflows it.
//
// Conversion is explicit and takes the decimal count, because the correct number is
// a property of the live runtime rather than a constant. See ChainProperties.

import (
	"fmt"
	"math/big"
	"strings"
)

// ParseAmount converts a decimal token amount to plancks.
//
// Accepts "1", "1.5", "0.000000000000000001", and a leading "+". Rejects more
// fractional digits than the chain supports rather than truncating.
//
//	ParseAmount("1.5", 12)   // 1500000000000
//	ParseAmount("0.0001", 3) // error: one digit too many for a 3-decimal chain
func ParseAmount(text string, decimals uint8) (*big.Int, error) {
	body := strings.TrimSpace(text)
	body = strings.TrimPrefix(body, "+")
	if body == "" {
		return nil, fmt.Errorf("invalid amount: amount is empty")
	}
	if strings.HasPrefix(body, "-") {
		return nil, fmt.Errorf("invalid amount: amount must not be negative")
	}

	whole, fraction, hasPoint := strings.Cut(body, ".")
	// "1." and ".5" are read differently by different people; require digits on
	// both sides of a point.
	if !isDigits(whole) || (hasPoint && !isDigits(fraction)) {
		return nil, fmt.Errorf("invalid amount: must be decimal digits with at most one point")
	}
	if len(fraction) > int(decimals) {
		return nil, fmt.Errorf(
			"invalid amount: %d fractional digits exceeds this chain's %d decimals",
			len(fraction), decimals)
	}

	// Right-pad the fraction to exactly `decimals` digits and read the whole thing
	// as one integer. No floating point at any step.
	digits := whole + fraction + strings.Repeat("0", int(decimals)-len(fraction))
	value, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount: %q is not a decimal number", text)
	}
	return value, nil
}

// FormatAmount renders plancks as a decimal string with no trailing zeros.
//
// Lossless: ParseAmount(FormatAmount(v, d), d) == v for every v.
//
//	FormatAmount(big.NewInt(1500000000000), 12) // "1.5"
//	FormatAmount(big.NewInt(1), 12)             // "0.000000000001"
func FormatAmount(plancks *big.Int, decimals uint8) string {
	if plancks == nil {
		return "0"
	}
	if decimals == 0 {
		return plancks.String()
	}

	digits := plancks.String()
	if len(digits) <= int(decimals) {
		digits = strings.Repeat("0", int(decimals)-len(digits)+1) + digits
	}
	split := len(digits) - int(decimals)
	whole, fraction := digits[:split], digits[split:]
	fraction = strings.TrimRight(fraction, "0")
	if fraction == "" {
		return whole
	}
	return whole + "." + fraction
}

// OneToken returns one whole token in plancks, i.e. 10^decimals.
func OneToken(decimals uint8) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
