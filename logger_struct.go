// Logger struct definition
// Moved from: logger.go
package go_i2cp

// Logger provides logging functionality for I2CP
type Logger struct {
	callbacks *LoggerCallbacks
	logLevel  int
}
