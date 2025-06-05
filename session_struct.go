// Session struct definition
// Moved from: session.go
package go_i2cp

// Session represents an I2CP session
type Session struct {
	id        uint16
	config    *SessionConfig
	client    *Client
	callbacks *SessionCallbacks
}
