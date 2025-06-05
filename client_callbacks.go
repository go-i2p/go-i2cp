package go_i2cp

// ClientCallBacks defines callback functions for client events.
// Moved from: client.go
type ClientCallBacks struct {
	opaque       *interface{}
	onDisconnect func(*Client, string, *interface{})
	onLog        func(*Client, LoggerTags, string)
}
