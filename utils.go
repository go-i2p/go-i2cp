package go_i2cp

import "strconv"

// NewCryptoInstance creates a new crypto instance
func NewCryptoInstance() *Crypto {
	return NewCrypto()
}

// parseIntWithDefault parses an integer string with a default value if parsing fails
// Note: Accepts "-" sign for negative numbers, but rejects "+" sign
func parseIntWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	// Reject strings with "+" sign (original behavior)
	if len(s) > 0 && s[0] == '+' {
		return defaultValue
	}

	result, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}

	return result
}
