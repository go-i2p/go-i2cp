package go_i2cp

// ClientCallBacks defines callback functions for client events.
// Moved from: client.go
type ClientCallBacks struct {
	Opaque            *interface{}
	OnConnect         func(*Client)
	OnDisconnect      func(*Client, string, *interface{})
	OnLog             func(*Client, LoggerTags, string)
	OnBandwidthLimits func(*Client, *BandwidthLimits)
}
