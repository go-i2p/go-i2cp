package go_i2cp

// NewCryptoInstance creates a new crypto instance
func NewCryptoInstance() *Crypto {
	return NewCrypto()
}

// parseIntWithDefault parses an integer string with a default value if parsing fails
func parseIntWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	negative, start := checkNegativeSign(s)
	if start >= len(s) {
		return defaultValue
	}

	result, valid := parseDigits(s, start)
	if !valid {
		return defaultValue
	}

	if negative {
		result = -result
	}

	return result
}

// checkNegativeSign checks if the string starts with a negative sign and returns the starting position for digit parsing.
func checkNegativeSign(s string) (negative bool, start int) {
	if len(s) > 0 && s[0] == '-' {
		return true, 1
	}
	return false, 0
}

// parseDigits parses digits from the string starting at the given position and returns the result and validity.
func parseDigits(s string, start int) (result int, valid bool) {
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		result = result*10 + int(s[i]-'0')
	}
	return result, true
}
