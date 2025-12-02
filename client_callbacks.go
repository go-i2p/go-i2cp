package go_i2cp

// ClientCallBacks defines callback functions for client-level events.
// All callbacks are optional and can be set to nil if not needed.
// Callbacks may be invoked from different goroutines, so implementations should be thread-safe.
//
// Example:
//
//	callbacks := &ClientCallBacks{
//	    OnConnect: func(c *Client) {
//	        log.Println("Connected to I2P router")
//	    },
//	    OnDisconnect: func(c *Client, reason string, opaque *interface{}) {
//	        log.Printf("Disconnected: %s", reason)
//	    },
//	    OnBandwidthLimits: func(c *Client, limits *BandwidthLimits) {
//	        log.Printf("Bandwidth limits: %s", limits.String())
//	    },
//	}
//	client := NewClient(callbacks)
type ClientCallBacks struct {
	// Opaque is user-defined data passed to disconnect callback.
	// Can be used to store custom context or state information.
	Opaque *interface{}

	// OnConnect is called when the client successfully connects to the I2P router.
	// This is invoked after the initial GetDate handshake completes.
	// Parameter:
	//   - client: The client that connected
	OnConnect func(*Client)

	// OnDisconnect is called when the client disconnects from the I2P router.
	// This may be triggered by network errors, router shutdown, or explicit disconnection.
	// Parameters:
	//   - client: The client that disconnected
	//   - reason: Reason for disconnection (e.g., "connection closed", "router shutdown")
	//   - opaque: User-defined data from Opaque field
	OnDisconnect func(*Client, string, *interface{})

	// OnLog is called for logging events with structured tags.
	// Allows custom log handling and integration with external logging systems.
	// Parameters:
	//   - client: The client generating the log
	//   - tags: Structured log tags (Debug, Info, Warn, Error)
	//   - message: Log message string
	OnLog func(*Client, LoggerTags, string)

	// OnBandwidthLimits is called when the router sends bandwidth limitation parameters.
	// I2CP 0.9.3+ - Enables rate limiting and traffic shaping based on router capacity.
	// Parameters:
	//   - client: The client receiving bandwidth limits
	//   - limits: Bandwidth limit parameters (inbound/outbound, burst, etc.)
	//
	// Example:
	//
	//	OnBandwidthLimits: func(c *Client, limits *BandwidthLimits) {
	//	    log.Printf("Router limits: inbound=%d, outbound=%d",
	//	               limits.RouterInbound, limits.RouterOutbound)
	//	    // Apply rate limiting using limits.ClientInbound/ClientOutbound
	//	}
	OnBandwidthLimits func(*Client, *BandwidthLimits)
}
