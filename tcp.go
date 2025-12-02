package go_i2cp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
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

var (
	defaultRouterAddress = "127.0.0.1:7654"
)

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
		USE_TLS = true
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

func (tcp *Tcp) Connect() (err error) {
	if tcp.address == nil {
		err := tcp.Init()
		if err != nil {
			return err
		}
	}
	if USE_TLS {
		roots, _ := x509.SystemCertPool()
		tcp.conn, err = tls.Dial("tcp", tcp.address.String(), &tls.Config{RootCAs: roots})
	} else {
		tcp.conn, err = net.Dial("tcp", tcp.address.String())
		if err != nil {
			return fmt.Errorf("i2cp: failed to dial TCP connection to %s: %w", tcp.address, err)
		}
	}
	return err
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
	properties [NR_OF_TCP_PROPERTIES]string
}
