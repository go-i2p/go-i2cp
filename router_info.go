package go_i2cp

// RouterInfo contains information about the I2P router.
// Moved from: client.go
type RouterInfo struct {
	date         uint64
	version      Version
	capabilities uint32
}
