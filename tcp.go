package go_i2cp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
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
	CAFile               = "/etc/ssl/certs/ca-certificates.crt"
	defaultRouterAddress = "127.0.0.1:7654"
)

func (tcp *Tcp) Init() (err error) {
	tcp.address, err = net.ResolveTCPAddr("tcp", defaultRouterAddress)
	return
}

func (tcp *Tcp) Connect() (err error) {
	if USE_TLS {
		roots, _ := x509.SystemCertPool()
		tcp.conn, err = tls.Dial("tcp", tcp.address.String(), &tls.Config{RootCAs: roots})
	} else {
		tcp.conn, err = net.Dial("tcp", tcp.address.String())
		if err != nil {
			return fmt.Errorf("i2cp: failed to dial TCP connection to %s: %w", tcp.address, err)
		}
		// Set keepalive if this is a TCP connection
		if tcpConn, ok := tcp.conn.(*net.TCPConn); ok {
			if err = tcpConn.SetKeepAlive(true); err != nil {
				// Non-fatal but should log
				Warning("Failed to set TCP keepalive for %s: %v", tcp.address, err)
			}
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
		Debug("%s detected closed LAN connection", tcp.address.String())
		defer tcp.Disconnect()
		return false
	} else {
		var zero time.Time
		tcp.conn.SetReadDeadline(zero)
		// Check if this is a TLS connection and verify handshake
		if tlsConn, ok := tcp.conn.(*tls.Conn); ok {
			return tlsConn.ConnectionState().HandshakeComplete
		}
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
	address    *net.TCPAddr
	conn       net.Conn
	properties [NR_OF_TCP_PROPERTIES]string
}
