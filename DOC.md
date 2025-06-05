# go_i2cp
--
    import "github.com/go-i2p/go-i2cp"

Crypto struct definition Moved from: crypto.go

LoggerCallbacks struct definition Moved from: logger.go

Logger struct definition Moved from: logger.go

SessionCallbacks struct definition Moved from: session.go

Session struct definition Moved from: session.go

SignatureKeyPair struct definition Moved from: crypto.go

## Usage

```go
const (
	PROTOCOL_STREAMING    = 6
	PROTOCOL_DATAGRAM     = 17
	PROTOCOL_RAW_DATAGRAM = 18
)
```
Protocol Constants Moved from: client.go

```go
const (
	HOST_LOOKUP_TYPE_HASH = iota
	HOST_LOOKUP_TYPE_HOST = iota
)
```
Host Lookup Type Constants Moved from: client.go

```go
const (
	CERTIFICATE_NULL     uint8 = iota
	CERTIFICATE_HASHCASH uint8 = iota
	CERTIFICATE_SIGNED   uint8 = iota
	CERTIFICATE_MULTIPLE uint8 = iota
)
```
Certificate Type Constants Moved from: certificate.go

```go
const (
	HASH_SHA1   uint8 = iota
	HASH_SHA256 uint8 = iota
)
```
Hash Algorithm Constants Moved from: crypto.go

```go
const (
	DSA_SHA1   uint32 = iota
	DSA_SHA256 uint32 = iota
)
```
Signature Algorithm Constants Moved from: crypto.go

```go
const (
	CODEC_BASE32 uint8 = iota
	CODEC_BASE64 uint8 = iota
)
```
Codec Algorithm Constants Moved from: crypto.go

```go
const (
	PROTOCOL = 1 << 0
	LOGIC    = 1 << 1

	DEBUG   = 1 << 4
	INFO    = 1 << 5
	WARNING = 1 << 6
	ERROR   = 1 << 7
	FATAL   = 1 << 8

	STRINGMAP      = 1 << 9
	INTMAP         = 1 << 10
	QUEUE          = 1 << 11
	STREAM         = 1 << 12
	CRYPTO         = 1 << 13
	TCP            = 1 << 14
	CLIENT         = 1 << 15
	CERTIFICATE    = 1 << 16
	LEASE          = 1 << 17
	DESTINATION    = 1 << 18
	SESSION        = 1 << 19
	SESSION_CONFIG = 1 << 20
	TEST           = 1 << 21
	DATAGRAM       = 1 << 22
	CONFIG_FILE    = 1 << 23
	VERSION        = 1 << 24

	TAG_MASK       = 0x0000000f
	LEVEL_MASK     = 0x000001f0
	COMPONENT_MASK = 0xfffffe00

	ALL = 0xffffffff
)
```
Logger Level Constants Moved from: logger.go

```go
const DEST_SIZE = 4096
```

```go
const DIGEST_SIZE = 40
```

```go
const I2CP_CLIENT_VERSION = "0.9.33"
```
I2CP Client Constants Moved from: client.go

```go
const I2CP_MAX_SESSIONS = 0xffff
```

```go
const I2CP_MAX_SESSIONS_PER_CLIENT = 32
```

```go
const I2CP_MESSAGE_SIZE = 0xffff
```

```go
const I2CP_MSG_ANY uint8 = 0
```
I2CP Message Type Constants Moved from: client.go

```go
const I2CP_MSG_BANDWIDTH_LIMITS uint8 = 23
```

```go
const I2CP_MSG_CREATE_LEASE_SET uint8 = 4
```

```go
const I2CP_MSG_CREATE_SESSION uint8 = 1
```

```go
const I2CP_MSG_DESTROY_SESSION uint8 = 3
```

```go
const I2CP_MSG_DEST_LOOKUP uint8 = 34
```

```go
const I2CP_MSG_DEST_REPLY uint8 = 35
```

```go
const I2CP_MSG_DISCONNECT uint8 = 30
```

```go
const I2CP_MSG_GET_BANDWIDTH_LIMITS uint8 = 8
```

```go
const I2CP_MSG_GET_DATE uint8 = 32
```

```go
const I2CP_MSG_HOST_LOOKUP uint8 = 38
```

```go
const I2CP_MSG_HOST_REPLY uint8 = 39
```

```go
const I2CP_MSG_MESSAGE_STATUS uint8 = 22
```

```go
const I2CP_MSG_PAYLOAD_MESSAGE uint8 = 31
```

```go
const I2CP_MSG_REQUEST_LEASESET uint8 = 21
```

```go
const I2CP_MSG_REQUEST_VARIABLE_LEASESET uint8 = 37
```

```go
const I2CP_MSG_SEND_MESSAGE uint8 = 5
```

```go
const I2CP_MSG_SESSION_STATUS uint8 = 20
```

```go
const I2CP_MSG_SET_DATE uint8 = 33
```

```go
const I2CP_PROTOCOL_INIT uint8 = 0x2a
```

```go
const PUB_KEY_SIZE = 256
```
Destination Size Constants Moved from: destination.go

```go
const ROUTER_CAN_HOST_LOOKUP uint32 = 1
```
Router Capabilities Constants Moved from: client.go

```go
const TAG = CLIENT
```

```go
const USE_TLS = false
```
TLS Constants Moved from: tcp.go

```go
var CAFile = "/etc/ssl/certs/ca-certificates.crt"
```

#### func  Debug

```go
func Debug(tags LoggerTags, message string, args ...interface{})
```

#### func  Error

```go
func Error(tags LoggerTags, message string, args ...interface{})
```

#### func  Fatal

```go
func Fatal(tags LoggerTags, message string, args ...interface{})
```

#### func  Info

```go
func Info(tags LoggerTags, message string, args ...interface{})
```

#### func  LogInit

```go
func LogInit(callbacks *LoggerCallbacks, level int)
```
TODO filter

#### func  ParseConfig

```go
func ParseConfig(s string, cb func(string, string))
```

#### func  Warning

```go
func Warning(tags LoggerTags, message string, args ...interface{})
```

#### type Certificate

```go
type Certificate struct {
}
```


#### func  NewCertificate

```go
func NewCertificate(typ uint8) (cert Certificate)
```

#### func  NewCertificateFromMessage

```go
func NewCertificateFromMessage(stream *Stream) (cert Certificate, err error)
```

#### func  NewCertificateFromStream

```go
func NewCertificateFromStream(stream *Stream) (Certificate, error)
```

#### func (*Certificate) Copy

```go
func (cert *Certificate) Copy() (newCert Certificate)
```

#### func (*Certificate) WriteToMessage

```go
func (cert *Certificate) WriteToMessage(stream *Stream) (err error)
```

#### func (*Certificate) WriteToStream

```go
func (cert *Certificate) WriteToStream(stream *Stream) error
```

#### type Client

```go
type Client struct {
}
```


#### func  NewClient

```go
func NewClient(callbacks *ClientCallBacks) (c *Client)
```
NewClient creates a new i2p client with the specified callbacks

#### func (*Client) Connect

```go
func (c *Client) Connect() error
```

#### func (*Client) CreateSession

```go
func (c *Client) CreateSession(sess *Session) error
```

#### func (*Client) DestinationLookup

```go
func (c *Client) DestinationLookup(session *Session, address string) (requestId uint32)
```

#### func (*Client) Disconnect

```go
func (c *Client) Disconnect()
```

#### func (*Client) IsConnected

```go
func (c *Client) IsConnected() bool
```

#### func (*Client) ProcessIO

```go
func (c *Client) ProcessIO() error
```

#### func (*Client) SetProperty

```go
func (c *Client) SetProperty(name, value string)
```

#### type ClientCallBacks

```go
type ClientCallBacks struct {
}
```

ClientCallBacks defines callback functions for client events. Moved from:
client.go

#### type ClientProperty

```go
type ClientProperty int
```


```go
const (
	CLIENT_PROP_ROUTER_ADDRESS ClientProperty = iota
	CLIENT_PROP_ROUTER_PORT
	CLIENT_PROP_ROUTER_USE_TLS
	CLIENT_PROP_USERNAME
	CLIENT_PROP_PASSWORD
	NR_OF_I2CP_CLIENT_PROPERTIES
)
```

#### type Crypto

```go
type Crypto struct {
}
```

Crypto provides cryptographic operations for I2CP

#### func  GetCryptoInstance

```go
func GetCryptoInstance() *Crypto
```

#### func (*Crypto) DecodeStream

```go
func (c *Crypto) DecodeStream(algorithmTyp uint8, src *Stream) (dst *Stream, err error)
```

#### func (*Crypto) EncodeStream

```go
func (c *Crypto) EncodeStream(algorithmTyp uint8, src *Stream) (dst *Stream)
```

#### func (*Crypto) HashStream

```go
func (c *Crypto) HashStream(algorithmTyp uint8, src *Stream) *Stream
```

#### func (*Crypto) PublicKeyFromStream

```go
func (c *Crypto) PublicKeyFromStream(keyType uint32, stream *Stream) (key *big.Int, err error)
```

#### func (*Crypto) SignStream

```go
func (c *Crypto) SignStream(sgk *SignatureKeyPair, stream *Stream) (err error)
```
Sign a stream using the specified algorithm

#### func (*Crypto) SignatureKeyPairFromStream

```go
func (c *Crypto) SignatureKeyPairFromStream(stream *Stream) (sgk SignatureKeyPair, err error)
```
Read and initialize signature keypair from stream

#### func (*Crypto) SignatureKeygen

```go
func (c *Crypto) SignatureKeygen(algorithmTyp uint32) (sgk SignatureKeyPair, err error)
```
Generate a signature keypair

#### func (*Crypto) VerifyStream

```go
func (c *Crypto) VerifyStream(sgk *SignatureKeyPair, stream *Stream) (verified bool, err error)
```
Verify Stream

#### func (*Crypto) WritePublicSignatureToStream

```go
func (c *Crypto) WritePublicSignatureToStream(sgk *SignatureKeyPair, stream *Stream) (err error)
```
Write public signature key to stream

#### func (*Crypto) WriteSignatureToStream

```go
func (c *Crypto) WriteSignatureToStream(sgk *SignatureKeyPair, stream *Stream) (err error)
```
Write Signature keypair to stream

#### type Destination

```go
type Destination struct {
}
```


#### func  NewDestination

```go
func NewDestination() (dest *Destination, err error)
```

#### func  NewDestinationFromBase64

```go
func NewDestinationFromBase64(base64 string) (dest *Destination, err error)
```

#### func  NewDestinationFromFile

```go
func NewDestinationFromFile(file *os.File) (*Destination, error)
```

#### func  NewDestinationFromMessage

```go
func NewDestinationFromMessage(stream *Stream) (dest *Destination, err error)
```

#### func  NewDestinationFromStream

```go
func NewDestinationFromStream(stream *Stream) (dest *Destination, err error)
```

#### func (*Destination) Copy

```go
func (dest *Destination) Copy() (newDest Destination)
```

#### func (*Destination) Verify

```go
func (dest *Destination) Verify() (verified bool, err error)
```
Doesn't seem to be used anywhere??

#### func (*Destination) WriteToFile

```go
func (dest *Destination) WriteToFile(filename string) (err error)
```

#### func (*Destination) WriteToMessage

```go
func (dest *Destination) WriteToMessage(stream *Stream) (err error)
```

#### func (*Destination) WriteToStream

```go
func (dest *Destination) WriteToStream(stream *Stream) (err error)
```

#### type Lease

```go
type Lease struct {
}
```


#### func  NewLeaseFromStream

```go
func NewLeaseFromStream(stream *Stream) (l *Lease, err error)
```

#### func (*Lease) WriteToMessage

```go
func (l *Lease) WriteToMessage(stream *Stream) (err error)
```

#### type Logger

```go
type Logger struct {
}
```

Logger provides logging functionality for I2CP

#### type LoggerCallbacks

```go
type LoggerCallbacks struct {
}
```

LoggerCallbacks provides callback functions for logging events

#### type LoggerTags

```go
type LoggerTags = uint32
```


#### type LookupEntry

```go
type LookupEntry struct {
}
```

LookupEntry represents a destination lookup request entry. Moved from: client.go

#### type RouterInfo

```go
type RouterInfo struct {
}
```

RouterInfo contains information about the I2P router. Moved from: client.go

#### type Session

```go
type Session struct {
}
```

Session represents an I2CP session

#### func  NewSession

```go
func NewSession(client *Client, callbacks SessionCallbacks) (sess *Session)
```

#### func (*Session) Destination

```go
func (session *Session) Destination() *Destination
```

#### func (*Session) SendMessage

```go
func (session *Session) SendMessage(destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32)
```

#### type SessionCallbacks

```go
type SessionCallbacks struct {
}
```

SessionCallbacks provides callback functions for session events

#### type SessionConfig

```go
type SessionConfig struct {
}
```


#### func  NewSessionConfigFromDestinationFile

```go
func NewSessionConfigFromDestinationFile(filename string) (config SessionConfig)
```

#### func (*SessionConfig) SetProperty

```go
func (config *SessionConfig) SetProperty(prop SessionConfigProperty, value string)
```

#### type SessionConfigProperty

```go
type SessionConfigProperty int
```


```go
const (
	SESSION_CONFIG_PROP_CRYPTO_LOW_TAG_THRESHOLD SessionConfigProperty = iota
	SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND

	SESSION_CONFIG_PROP_I2CP_DONT_PUBLISH_LEASE_SET
	SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE
	SESSION_CONFIG_PROP_I2CP_GZIP
	SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY
	SESSION_CONFIG_PROP_I2CP_PASSWORD
	SESSION_CONFIG_PROP_I2CP_USERNAME

	SESSION_CONFIG_PROP_INBOUND_ALLOW_ZERO_HOP
	SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY
	SESSION_CONFIG_PROP_INBOUND_IP_RESTRICTION
	SESSION_CONFIG_PROP_INBOUND_LENGTH
	SESSION_CONFIG_PROP_INBOUND_LENGTH_VARIANCE
	SESSION_CONFIG_PROP_INBOUND_NICKNAME
	SESSION_CONFIG_PROP_INBOUND_QUANTITY

	SESSION_CONFIG_PROP_OUTBOUND_ALLOW_ZERO_HOP
	SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY
	SESSION_CONFIG_PROP_OUTBOUND_IP_RESTRICTION
	SESSION_CONFIG_PROP_OUTBOUND_LENGTH
	SESSION_CONFIG_PROP_OUTBOUND_LENGTH_VARIANCE
	SESSION_CONFIG_PROP_OUTBOUND_NICKNAME
	SESSION_CONFIG_PROP_OUTBOUND_PRIORITY
	SESSION_CONFIG_PROP_OUTBOUND_QUANTITY

	NR_OF_SESSION_CONFIG_PROPERTIES
)
```

#### type SessionMessageStatus

```go
type SessionMessageStatus int
```

Session Message Status Constants Moved from: session.go

```go
const (
	I2CP_MSG_STATUS_AVAILABLE SessionMessageStatus = iota
	I2CP_MSG_STATUS_ACCEPTED
	I2CP_MSG_STATUS_BEST_EFFORT_SUCCESS
	I2CP_MSG_STATUS_BEST_EFFORT_FAILURE
	I2CP_MSG_STATUS_GUARANTEED_SUCCESS
	I2CP_MSG_STATUS_GUARANTEED_FAILURE
	I2CP_MSG_STATUS_LOCAL_SUCCESS
	I2CP_MSG_STATUS_LOCAL_FAILURE
	I2CP_MSG_STATUS_ROUTER_FAILURE
	I2CP_MSG_STATUS_NETWORK_FAILURE
	I2CP_MSG_STATUS_BAD_SESSION
	I2CP_MSG_STATUS_BAD_MESSAGE
	I2CP_MSG_STATUS_OVERFLOW_FAILURE
	I2CP_MSG_STATUS_MESSAGE_EXPIRED
	I2CP_MSG_STATUS_MESSAGE_BAD_LOCAL_LEASESET
	I2CP_MSG_STATUS_MESSAGE_NO_LOCAL_TUNNELS
	I2CP_MSG_STATUS_MESSAGE_UNSUPPORTED_ENCRYPTION
	I2CP_MSG_STATUS_MESSAGE_BAD_DESTINATION
	I2CP_MSG_STATUS_MESSAGE_BAD_LEASESET
	I2CP_MSG_STATUS_MESSAGE_EXPIRED_LEASESET
	I2CP_MSG_STATUS_MESSAGE_NO_LEASESET
)
```

#### type SessionStatus

```go
type SessionStatus int
```

Session Status Constants Moved from: session.go

```go
const (
	I2CP_SESSION_STATUS_DESTROYED SessionStatus = iota
	I2CP_SESSION_STATUS_CREATED
	I2CP_SESSION_STATUS_UPDATED
	I2CP_SESSION_STATUS_INVALID
)
```

#### type SignatureKeyPair

```go
type SignatureKeyPair struct {
}
```

SignatureKeyPair represents a DSA signature key pair

#### type Stream

```go
type Stream struct {
	*bytes.Buffer
}
```


#### func  NewStream

```go
func NewStream(buf []byte) (s *Stream)
```

#### func (*Stream) ChLen

```go
func (s *Stream) ChLen(len int)
```

#### func (*Stream) ReadUint16

```go
func (s *Stream) ReadUint16() (r uint16, err error)
```

#### func (*Stream) ReadUint32

```go
func (s *Stream) ReadUint32() (r uint32, err error)
```

#### func (*Stream) ReadUint64

```go
func (s *Stream) ReadUint64() (r uint64, err error)
```

#### func (*Stream) WriteLenPrefixedString

```go
func (stream *Stream) WriteLenPrefixedString(s string) (err error)
```

#### func (*Stream) WriteMapping

```go
func (stream *Stream) WriteMapping(m map[string]string) (err error)
```

#### func (*Stream) WriteUint16

```go
func (s *Stream) WriteUint16(i uint16) (err error)
```

#### func (*Stream) WriteUint32

```go
func (s *Stream) WriteUint32(i uint32) (err error)
```

#### func (*Stream) WriteUint64

```go
func (s *Stream) WriteUint64(i uint64) (err error)
```

#### type Tcp

```go
type Tcp struct {
}
```


#### func (*Tcp) CanRead

```go
func (tcp *Tcp) CanRead() bool
```

#### func (*Tcp) Connect

```go
func (tcp *Tcp) Connect() (err error)
```

#### func (*Tcp) Disconnect

```go
func (tcp *Tcp) Disconnect()
```

#### func (*Tcp) GetProperty

```go
func (tcp *Tcp) GetProperty(property TcpProperty) string
```

#### func (*Tcp) Init

```go
func (tcp *Tcp) Init() (err error)
```

#### func (*Tcp) IsConnected

```go
func (tcp *Tcp) IsConnected() bool
```

#### func (*Tcp) Receive

```go
func (tcp *Tcp) Receive(buf *Stream) (i int, err error)
```

#### func (*Tcp) Send

```go
func (tcp *Tcp) Send(buf *Stream) (i int, err error)
```

#### func (*Tcp) SetProperty

```go
func (tcp *Tcp) SetProperty(property TcpProperty, value string)
```

#### type TcpProperty

```go
type TcpProperty int
```


```go
const (
	TCP_PROP_ADDRESS TcpProperty = iota
	TCP_PROP_PORT
	TCP_PROP_USE_TLS
	TCP_PROP_TLS_CLIENT_CERTIFICATE
	NR_OF_TCP_PROPERTIES
)
```

#### type Version

```go
type Version struct {
}
```
