// LoggerCallbacks struct definition
// Moved from: logger.go
package go_i2cp

// LoggerCallbacks provides callback functions for logging events
type LoggerCallbacks struct {
	opaque *interface{}
	onLog  func(*Logger, LoggerTags, string)
}
