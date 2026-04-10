package go_i2cp

import (
"context"
"fmt"
"time"
)


// Connect establishes a connection to the I2P router with context support.
// The context can be used to cancel the connection attempt or set a timeout.
// Implements proper error path cleanup with defer pattern per PLAN.md section 1.3.
// Supports TLS connections per I2CP 0.8.3+ specification (authentication method 2).
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	err := client.Connect(ctx)
func (c *Client) Connect(ctx context.Context) error {
	if err := c.validateConnectionPreconditions(ctx); err != nil {
		return err
	}

	Info("Client connecting to i2cp at %s:%s", c.properties["i2cp.tcp.host"], c.properties["i2cp.tcp.port"])

	if err := c.establishConnection(ctx); err != nil {
		return err
	}

	c.updateConnectionMetrics()
	return nil
}

// validateConnectionPreconditions checks if client is initialized and context is valid.
func (c *Client) validateConnectionPreconditions(ctx context.Context) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before connect: %w", err)
	}

	return nil
}

// establishConnection sets up TLS, connects TCP, and performs protocol handshake.
func (c *Client) establishConnection(ctx context.Context) error {
	if err := c.setupTLSIfEnabled(); err != nil {
		return err
	}

	if err := c.connectTCP(); err != nil {
		return err
	}

	success := false
	defer func() {
		if !success {
			Debug("Connect failed - cleaning up TCP connection")
			c.tcp.Disconnect()
			c.connected = false
		}
	}()

	if err := c.performProtocolHandshake(ctx); err != nil {
		return err
	}

	c.connected = true
	success = true

	// Invoke OnConnect callback after successful handshake
	if c.callbacks != nil && c.callbacks.OnConnect != nil {
		c.callbacks.OnConnect(c)
	}

	return nil
}

// connectTCP establishes the TCP/TLS connection to the router.
func (c *Client) connectTCP() error {
	err := c.tcp.Connect()
	if err != nil {
		c.trackError("network")
		return fmt.Errorf("failed to connect TCP: %w", err)
	}
	return nil
}

// updateConnectionMetrics updates metrics to reflect connected state.
func (c *Client) updateConnectionMetrics() {
	if c.metrics != nil {
		c.metrics.SetConnectionState("connected")
	}
}

// setupTLSIfEnabled configures TLS for the TCP connection if enabled in client properties.
// It reads TLS configuration from client properties and applies them to the TCP layer.
func (c *Client) setupTLSIfEnabled() error {
	if c.properties["i2cp.SSL"] != "true" {
		return nil
	}

	certFile := c.properties["i2cp.SSL.certFile"]
	keyFile := c.properties["i2cp.SSL.keyFile"]
	caFile := c.properties["i2cp.SSL.caFile"]
	insecure := c.properties["i2cp.SSL.insecure"] == "true"

	Debug("Configuring TLS: certFile=%s, keyFile=%s, caFile=%s, insecure=%v",
		certFile, keyFile, caFile, insecure)

	err := c.tcp.SetupTLS(certFile, keyFile, caFile, insecure)
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	Info("TLS configured successfully")
	return nil
}

// performProtocolHandshake executes the I2CP protocol initialization sequence.
// It sends the protocol init byte, GetDate message, and waits for SetDate response.
func (c *Client) performProtocolHandshake(ctx context.Context) error {
	// Check context after TCP connect
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled after TCP connect: %w", err)
	}

	// Send protocol initialization byte
	if err := c.sendProtocolInit(); err != nil {
		return err
	}

	Debug("Sending protocol byte message")

	// Send GetDate message
	c.msgGetDate(false)

	// Receive SetDate response with context checking
	return c.receiveSetDateWithContext(ctx)
}

// sendProtocolInit sends the I2CP protocol initialization byte to the router.
// It uses circuit breaker if available to protect against connection issues.
func (c *Client) sendProtocolInit() error {
	c.outputStream.Reset()
	c.outputStream.WriteByte(I2CP_PROTOCOL_INIT)

	var err error
	if c.circuitBreaker != nil {
		err = c.circuitBreaker.Execute(func() error {
			_, sendErr := c.tcp.Send(c.outputStream)
			return sendErr
		})
	} else {
		_, err = c.tcp.Send(c.outputStream)
	}

	if err != nil {
		return fmt.Errorf("failed to send protocol init: %w", err)
	}

	return nil
}

// receiveSetDateWithContext receives the SetDate response message with context cancellation support.
// It runs the receive operation in a goroutine to allow context cancellation.
func (c *Client) receiveSetDateWithContext(ctx context.Context) error {
	type result struct {
		err error
	}
	resultChan := make(chan result, 1)

	go func() {
		err := c.recvMessage(I2CP_MSG_SET_DATE, c.receiveStream, true)
		resultChan <- result{err: err}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled during SetDate receive: %w", ctx.Err())
	case res := <-resultChan:
		if res.err != nil {
			return fmt.Errorf("failed to receive SetDate: %w", res.err)
		}
	}

	return nil
}

// CreateSession creates a new I2P session with context support.
// The context can be used to cancel the session creation or set a timeout.
//
// IMPORTANT: You must run ProcessIO() in a background goroutine BEFORE calling CreateSession.
// The session creation response (SessionStatusMessage) will be received and processed by ProcessIO.
// The session status callback will be invoked when the router confirms session creation.
//
// Example:
//
//	// Start ProcessIO in background
//	go func() {
//	    for {
//	        if err := client.ProcessIO(ctx); err != nil {
//	            // Handle error
//	            return
//	        }
//	        time.Sleep(100 * time.Millisecond)
//	    }
//	}()
//
//	// Create session
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	err := client.CreateSession(ctx, session)
//
// The session will be confirmed via the OnStatus callback in SessionCallbacks.
// validateAndConfigureSubsession validates subsession requirements and inherits configuration from the primary session.
// It checks router version compatibility and copies all configuration properties from the primary session.
// Returns error if subsession is invalid or router version is insufficient.
func (c *Client) validateAndConfigureSubsession(sess *Session) error {
	primary := sess.PrimarySession()
	if primary == nil {
		return fmt.Errorf("subsession requires a primary session reference")
	}

	if err := c.checkSubsessionRouterVersion(); err != nil {
		return err
	}

	inheritPrimarySessionConfig(sess, primary)
	return nil
}

// checkSubsessionRouterVersion verifies the router supports multi-session feature (I2CP 0.9.21+).
func (c *Client) checkSubsessionRouterVersion() error {
	minVersion := Version{major: 0, minor: 9, micro: 21, qualifier: 0}
	if c.router.version.compare(minVersion) < 0 {
		return fmt.Errorf("router version %v does not support multi-session (requires >= 0.9.21)", c.router.version)
	}
	return nil
}

// inheritPrimarySessionConfig copies all configuration properties from the primary to the subsession.
// Per Java I2P reference: ClientMessageEventListener.java:280-388
// "all the primary options, then the overrides from the alias"
func inheritPrimarySessionConfig(sess, primary *Session) {
	if primary.config == nil {
		return
	}
	for i := SessionConfigProperty(0); i < NR_OF_SESSION_CONFIG_PROPERTIES; i++ {
		value := primary.config.GetProperty(i)
		if value != "" {
			sess.config.SetProperty(i, value)
		}
	}
	Debug("Subsession inherited configuration from primary session %d", primary.ID())
}

// disableSubsessionTunnels overrides tunnel settings for subsessions to prevent tunnel creation.
// Per I2CP 0.9.21+ spec, subsessions share the primary session's tunnels and do not create their own.
func disableSubsessionTunnels(sess *Session) {
	sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "0")
	Debug("Subsession tunnel creation disabled (sharing primary's tunnels)")
}

// configureFastReceiveMode enables or disables fast receive mode based on router version.
// Modern routers (I2CP 0.9.4+) send PayloadMessage (type 31) instead of deprecated
// ReceiveMessageBegin/End (types 6/7) messages.
func (c *Client) configureFastReceiveMode(sess *Session) {
	if c.router.version.compare(Version{major: 0, minor: 9, micro: 4, qualifier: 0}) >= 0 {
		sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		Debug("Router %v supports fastReceive mode", c.router.version)
	} else {
		// Legacy router - do not set fastReceive, expecting ReceiveMessageBegin/End
		Warning("Router version %v does not support fastReceive mode (requires >= 0.9.4)", c.router.version)
	}
}

// CreateSession creates a new I2CP session with the router.
// This initiates session establishment which completes asynchronously via ProcessIO.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sess: Session configuration and callbacks
//
// Returns error if validation fails or message cannot be sent.
// Success is confirmed via OnStatus callback with I2CP_SESSION_STATUS_CREATED.
//
// I2CP Spec: CreateSessionMessage (type 1), I2CP 0.9.21+ for multi-session support
func (c *Client) CreateSession(ctx context.Context, sess *Session) error {
	if err := c.validateSessionCreationPrerequisites(ctx, sess); err != nil {
		return err
	}

	if err := c.configureSessionProperties(sess); err != nil {
		return err
	}

	if err := c.sendSessionCreationRequest(sess); err != nil {
		return err
	}

	return nil
}

// validateSessionCreationPrerequisites checks all preconditions required to create a session.
// Returns an error if client is not initialized, session is nil, context is cancelled,
// or maximum sessions limit is reached.
func (c *Client) validateSessionCreationPrerequisites(ctx context.Context, sess *Session) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	if sess == nil {
		return fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before session creation: %w", err)
	}

	if c.n_sessions == I2CP_MAX_SESSIONS_PER_CLIENT {
		Warning("Maximum number of session per client connection reached.")
		return ErrMaxSessionsReached
	}

	return nil
}

// configureSessionProperties applies session configuration based on type and router capabilities.
// Handles subsession configuration, fast receive mode, and message reliability settings.
func (c *Client) configureSessionProperties(sess *Session) error {
	if !sess.IsPrimary() {
		if err := c.validateAndConfigureSubsession(sess); err != nil {
			return err
		}
		disableSubsessionTunnels(sess)
	}

	c.configureFastReceiveMode(sess)
	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	return nil
}

// sendSessionCreationRequest sends the CreateSession message to the router and updates metrics.
// The session status response will be processed asynchronously by ProcessIO.
// Thread-safe: uses sessionMu to protect currentSession assignment.
func (c *Client) sendSessionCreationRequest(sess *Session) error {
	if err := c.msgCreateSession(sess.config, false); err != nil {
		return fmt.Errorf("failed to send CreateSession message: %w", err)
	}

	c.sessionMu.Lock()
	c.currentSession = sess
	c.sessionMu.Unlock()

	Debug("CreateSession message sent, waiting for SessionCreated response...")
	Debug("IMPORTANT: Ensure ProcessIO() is running in background to receive response")

	if c.metrics != nil {
		c.lock.Lock()
		c.metrics.SetActiveSessions(len(c.sessions))
		c.lock.Unlock()
	}

	return nil
}

func (c *Client) EnableAutoReconnect(maxRetries int, initialBackoff time.Duration) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.reconnectEnabled = true
	c.reconnectMaxRetries = maxRetries
	c.reconnectBackoff = initialBackoff
	c.reconnectAttempts = 0

	Debug("Auto-reconnect enabled: maxRetries=%d, initialBackoff=%v", maxRetries, initialBackoff)
}

// DisableAutoReconnect disables automatic reconnection.
func (c *Client) DisableAutoReconnect() {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.reconnectEnabled = false
	Debug("Auto-reconnect disabled")
}

// IsAutoReconnectEnabled returns whether auto-reconnect is currently enabled.
func (c *Client) IsAutoReconnectEnabled() bool {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	return c.reconnectEnabled
}

// ReconnectAttempts returns the current number of reconnection attempts.
func (c *Client) ReconnectAttempts() int {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	return c.reconnectAttempts
}

// autoReconnect attempts to reconnect to the I2P router with exponential backoff.
// This is called internally when a disconnect is detected and auto-reconnect is enabled.
// It returns nil if reconnection succeeds, or an error if all retries are exhausted.
func (c *Client) autoReconnect(ctx context.Context) error {
	maxRetries, initialBackoff, err := c.getReconnectConfig()
	if err != nil {
		return err
	}

	Info("Starting auto-reconnect (maxRetries=%d, initialBackoff=%v)", maxRetries, initialBackoff)

	if err := RetryWithBackoff(ctx, maxRetries, initialBackoff, c.attemptReconnect); err != nil {
		Error("Auto-reconnect failed after all retries: %v", err)
		return fmt.Errorf("auto-reconnect failed: %w", err)
	}
	return nil
}

// getReconnectConfig retrieves reconnection configuration from the client.
func (c *Client) getReconnectConfig() (int, time.Duration, error) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	if !c.reconnectEnabled {
		return 0, 0, fmt.Errorf("auto-reconnect is not enabled")
	}
	return c.reconnectMaxRetries, c.reconnectBackoff, nil
}

// attemptReconnect performs a single reconnection attempt.
func (c *Client) attemptReconnect() error {
	c.reconnectMu.Lock()
	c.reconnectAttempts++
	attempt := c.reconnectAttempts
	c.reconnectMu.Unlock()

	Info("Reconnection attempt %d", attempt)

	if err := c.Connect(context.Background()); err != nil {
		Warning("Reconnection attempt %d failed: %v", attempt, err)
		return err
	}

	Info("Reconnection attempt %d succeeded!", attempt)
	c.reconnectMu.Lock()
	c.reconnectAttempts = 0
	c.reconnectMu.Unlock()

	return nil
}

