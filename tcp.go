package go_i2cp

import (
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

func (tcp *Tcp) Connect() (err error) {
	if tcp.address == nil {
		err := tcp.Init()
		if err != nil {
			return err
		}
	}

	// Use TLS if configured via SetupTLS
	if tcp.tlsConfig != nil {
		// TLS configuration has been set up via SetupTLS

		Debug("Establishing TLS connection to %s", tcp.address.String())
		tcp.conn, err = tls.Dial("tcp", tcp.address.String(), tcp.tlsConfig)
		if err != nil {
			return fmt.Errorf("i2cp: failed to dial TLS connection to %s: %w", tcp.address, err)
		}

		// Verify TLS handshake completed successfully
		if tlsConn, ok := tcp.conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				tcp.conn.Close()
				tcp.conn = nil
				return fmt.Errorf("i2cp: TLS handshake failed: %w", err)
			}
			state := tlsConn.ConnectionState()
			Debug("TLS connection established: version=%s cipher=%s",
				tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
		}
	} else {
		// Plain TCP connection
		Debug("Establishing TCP connection to %s", tcp.address.String())
		tcp.conn, err = net.Dial("tcp", tcp.address.String())
		if err != nil {
			return fmt.Errorf("i2cp: failed to dial TCP connection to %s: %w", tcp.address, err)
		}
	}

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
	i, err = tcp.conn.Read(buf.Bytes())
	return
}

func (tcp *Tcp) CanRead() bool {
	var one []byte
	if tcp.conn == nil {
		return false
	}
	tcp.conn.SetReadDeadline(time.Now())
	if _, err := tcp.conn.Read(one); err == io.EOF {
		if tcp.address != nil {
			Debug("%s detected closed LAN connection", tcp.address.String())
		}
		defer tcp.Disconnect()
		return false
	} else {
		var zero time.Time
		tcp.conn.SetReadDeadline(zero)
		return true
	}
}

func (tcp *Tcp) Disconnect() {
	if tcp.conn != nil {
		tcp.conn.Close()
	}
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
	tlsConfig  *tls.Config
	properties [NR_OF_TCP_PROPERTIES]string
}
