package go_i2cp

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"
)

type TcpProperty int

const (
	TCP_PROP_ADDRESS TcpProperty = iota
	TCP_PROP_PORT
	TCP_PROP_USE_TLS
	TCP_PROP_TLS_CLIENT_CERTIFICATE
	NR_OF_TCP_PROPERTIES
)

var defaultRouterAddress = "127.0.0.1:7654"

func ResolveAddr(address string) (net.Addr, error) {
	// check if the address contains a scheme to extract.
	// If it does not, determine if it is an IP:Port or a unix socket path.
	if scheme, err := url.Parse(address); err != nil || scheme.Scheme == "" {
		if _, _, err := net.SplitHostPort(address); err != nil {
			// treat as unix socket path
			address = "unix://" + address
		} else {
			// treat as tcp address
			address = "tcp://" + address
		}
	}
	// extract the scheme, host, and port
	scheme, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	host := scheme.Hostname()
	port := scheme.Port()
	if port == "" {
		port = "7654" // default I2CP port
	}
	switch scheme.Scheme {
	case "tcp":
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	case "tls":
		// TLS scheme detected - caller should call SetupTLS before Connect
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	case "unix":
		return net.ResolveUnixAddr("unix", scheme.Path)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", scheme.Scheme)
	}
}

func (tcp *Tcp) Init(routerAddress ...string) (err error) {
	addrString := defaultRouterAddress
	if len(routerAddress) > 0 {
		addrString = routerAddress[0]
	}
	addr, err := ResolveAddr(addrString)
	if err == nil {
		tcp.address = addr
	}
	return
}

// SetupTLS configures TLS for the TCP connection per I2CP 0.8.3+ specification.
// It loads client certificates, CA certificates, and configures TLS settings.
// The insecure parameter allows skipping certificate verification (development only).
//
// Parameters:
//   - certFile: Path to client certificate file (PEM format)
//   - keyFile: Path to client private key file (PEM format)
//   - caFile: Path to CA certificate file (PEM format, optional)
//   - insecure: If true, skip certificate verification (NOT for production)
//
// Returns error if certificate loading fails or TLS configuration is invalid.
func (tcp *Tcp) SetupTLS(certFile, keyFile, caFile string, insecure bool) error {
	tcp.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, // I2CP requires TLS 1.2+ for security
	}

	// Load client certificate if provided (for mutual TLS authentication)
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		tcp.tlsConfig.Certificates = []tls.Certificate{cert}
		Debug("Loaded client certificate from %s", certFile)
	}

	// Load CA certificate if provided (for server certificate validation)
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
		tcp.tlsConfig.RootCAs = caPool
		Debug("Loaded CA certificate from %s", caFile)
	} else {
		// Use system CA pool if no custom CA provided
		if roots, err := x509.SystemCertPool(); err == nil {
			tcp.tlsConfig.RootCAs = roots
			Debug("Using system CA certificate pool")
		} else {
			Warning("Failed to load system CA pool: %v", err)
			// Create empty pool as fallback
			tcp.tlsConfig.RootCAs = x509.NewCertPool()
		}
	}

	// Configure insecure mode (development/testing only)
	if insecure {
		Warning("TLS certificate verification DISABLED - insecure mode active")
		tcp.tlsConfig.InsecureSkipVerify = true
	} else {
		tcp.tlsConfig.InsecureSkipVerify = false
	}

	return nil
}

// Connect establishes a TCP or TLS connection to the I2P router.
// Initializes the connection address if needed, then establishes either
// a TLS connection (if configured) or plain TCP connection.
func (tcp *Tcp) Connect() (err error) {
	if err := tcp.ensureAddressInitialized(); err != nil {
		return err
	}

	if tcp.tlsConfig != nil {
		if err := tcp.connectTLS(); err != nil {
			return err
		}
	} else {
		if err := tcp.connectTCP(); err != nil {
			return err
		}
	}

	tcp.reader = bufio.NewReader(tcp.conn)
	return nil
}

// ensureAddressInitialized verifies the connection address is set,
// initializing it if necessary.
func (tcp *Tcp) ensureAddressInitialized() error {
	if tcp.address == nil {
		if err := tcp.Init(); err != nil {
			return err
		}
	}
	return nil
}

// connectTLS establishes a TLS connection and verifies the handshake.
func (tcp *Tcp) connectTLS() error {
	Debug("Establishing TLS connection to %s", tcp.address.String())
	conn, err := tls.Dial("tcp", tcp.address.String(), tcp.tlsConfig)
	if err != nil {
		return fmt.Errorf("i2cp: failed to dial TLS connection to %s: %w", tcp.address, err)
	}

	if err := tcp.verifyTLSHandshake(conn); err != nil {
		conn.Close()
		return err
	}

	tcp.conn = conn
	return nil
}

// verifyTLSHandshake completes and validates the TLS handshake.
func (tcp *Tcp) verifyTLSHandshake(conn net.Conn) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}

	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("i2cp: TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	Debug("TLS connection established: version=%s cipher=%s",
		tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
	return nil
}

// connectTCP establishes a plain TCP connection.
func (tcp *Tcp) connectTCP() error {
	Debug("Establishing TCP connection to %s", tcp.address.String())
	conn, err := net.Dial("tcp", tcp.address.String())
	if err != nil {
		return fmt.Errorf("i2cp: failed to dial TCP connection to %s: %w", tcp.address, err)
	}
	tcp.conn = conn
	return nil
}

func (tcp *Tcp) Send(buf *Stream) (i int, err error) {
	if tcp.conn == nil {
		return 0, fmt.Errorf("connection not established")
	}
	i, err = tcp.conn.Write(buf.Bytes())
	return
}

func (tcp *Tcp) Receive(buf *Stream) (i int, err error) {
	// Use buffered reader to preserve data consumed by CanRead()
	if tcp.reader != nil {
		i, err = tcp.reader.Read(buf.Bytes())
	} else {
		i, err = tcp.conn.Read(buf.Bytes())
	}
	return
}

func (tcp *Tcp) CanRead() bool {
	if tcp.conn == nil {
		return false
	}

	// Use buffered reader's Peek() for non-destructive data availability check
	// This fixes the critical bug where CanRead() consumed bytes from the stream
	if tcp.reader != nil {
		return canReadBuffered(tcp)
	}

	// Fallback for unbuffered connection (should not occur in normal operation)
	return canReadUnbuffered(tcp)
}

// canReadBuffered checks if data is available using buffered reader's Peek.
// Returns true if data is available, false otherwise.
func canReadBuffered(tcp *Tcp) bool {
	err := peekBufferedData(tcp)

	if err == nil {
		// Data is available and buffered
		return true
	}

	return handleReadError(tcp, err)
}

// peekBufferedData attempts to peek at one byte with a timeout to avoid blocking.
// Returns nil if data is available, error otherwise.
func peekBufferedData(tcp *Tcp) error {
	// Set a short read deadline to prevent blocking indefinitely
	// This prevents CanRead() from hanging on closed or unresponsive connections
	deadline := time.Now().Add(1 * time.Millisecond)
	tcp.conn.SetReadDeadline(deadline)

	// Peek at 1 byte without consuming it from the buffer
	_, err := tcp.reader.Peek(1)

	// Reset deadline to zero (blocking mode) for actual message reads
	var zero time.Time
	tcp.conn.SetReadDeadline(zero)

	return err
}

// handleReadError processes errors from read operations and determines availability.
// Returns false for EOF, timeout, or other errors.
func handleReadError(tcp *Tcp, err error) bool {
	// Handle EOF (connection closed)
	if err == io.EOF {
		if tcp.address != nil {
			Debug("%s detected closed connection", tcp.address.String())
		}
		defer tcp.Disconnect()
		return false
	}

	// Check for timeout (expected when no data available)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return false
	}

	// Other errors also indicate connection issues
	return false
}

// canReadUnbuffered checks data availability without buffered reader.
// This is a fallback path that consumes one byte from the stream.
func canReadUnbuffered(tcp *Tcp) bool {
	// Set a very short read deadline (1ms) to check data availability without blocking
	deadline := time.Now().Add(1 * time.Millisecond)
	tcp.conn.SetReadDeadline(deadline)

	// Try to peek at one byte
	one := make([]byte, 1)
	_, err := tcp.conn.Read(one)

	// Always reset deadline to zero (blocking mode) for actual message reads
	var zero time.Time
	tcp.conn.SetReadDeadline(zero)

	// Handle different error conditions
	if err == io.EOF {
		if tcp.address != nil {
			Debug("%s detected closed connection", tcp.address.String())
		}
		defer tcp.Disconnect()
		return false
	}

	if err != nil {
		// Check for timeout (expected when no data available)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}
		Debug("CanRead error (non-timeout): %v", err)
		return false
	}

	// Data available (but 1 byte was consumed - only in fallback path)
	Warning("CanRead: Used fallback path that consumes data - reader not initialized")
	return true
}

func (tcp *Tcp) Disconnect() {
	if tcp.conn != nil {
		tcp.conn.Close()
		tcp.conn = nil
	}
	// Reset buffered reader to prevent blocking on closed connections
	tcp.reader = nil
}

func (tcp *Tcp) IsConnected() bool {
	return tcp.CanRead()
}

func (tcp *Tcp) SetProperty(property TcpProperty, value string) {
	tcp.properties[property] = value
}

func (tcp *Tcp) GetProperty(property TcpProperty) string {
	return tcp.properties[property]
}

type Tcp struct {
	address    net.Addr
	conn       net.Conn
	reader     *bufio.Reader // Buffered reader for non-destructive peeking (fixes CanRead() bug)
	tlsConfig  *tls.Config
	properties [NR_OF_TCP_PROPERTIES]string
}
