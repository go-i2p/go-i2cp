package go_i2cp

import (
	"bytes"
	"compress/zlib"
	"net"
	"testing"
)

// streamHandlerTest is a table-driven test case for a Client message handler
// that operates on a raw Stream. setupClient is optional: when non-nil, it
// customizes the Client returned by the newClient factory before the handler runs.
type streamHandlerTest struct {
	name        string
	setupStream func() *Stream
	setupClient func(*Client)
	description string
}

// newTestClient creates a Client with the given sessions map for message-handler
// error-path tests.
func newTestClient(sessions map[uint16]*Session) *Client {
	return &Client{sessions: sessions}
}

// runStreamHandlerTests runs each streamHandlerTest as a subtest: it builds a
// fresh Client via newClient, applies the test case's optional setupClient,
// builds the input stream, and invokes handler.
func runStreamHandlerTests(t *testing.T, tests []streamHandlerTest, newClient func() *Client, handler func(*Client, *Stream)) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newClient()
			if tt.setupClient != nil {
				tt.setupClient(client)
			}
			stream := tt.setupStream()
			handler(client, stream)
			t.Logf("Test scenario: %s", tt.description)
		})
	}
}

// TestOnMsgPayloadErrorPaths tests error handling in onMsgPayload message handler
func TestOnMsgPayloadErrorPaths(t *testing.T) {
	tests := []streamHandlerTest{
		{
			name: "empty stream - sessionId read fails",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			description: "Should fail when stream is too short to read sessionId",
		},
		{
			name: "incomplete sessionId - only 1 byte",
			setupStream: func() *Stream {
				return NewStream([]byte{0x00})
			},
			description: "Should fail when sessionId is incomplete",
		},
		{
			name: "sessionId present but messageId missing",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				return stream
			},
			description: "Should fail when messageId cannot be read",
		},
		{
			name: "invalid zlib compressed data",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)                         // sessionId
				stream.WriteUint32(42)                        // messageId
				invalidZlib := []byte{0xFF, 0xFF, 0xFF, 0xFF} // Invalid zlib header
				stream.WriteUint32(uint32(len(invalidZlib)))  // size
				stream.Write(invalidZlib)                     // Invalid compressed data
				return stream
			},
			description: "Should fail when zlib decompression fails",
		},
		{
			name: "valid compressed payload",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)  // sessionId
				stream.WriteUint32(42) // messageId

				// Create valid zlib compressed data
				var compressed bytes.Buffer
				w := zlib.NewWriter(&compressed)
				testData := []byte("test payload data")
				w.Write(testData)
				w.Close()

				compressedData := compressed.Bytes()
				stream.WriteUint32(uint32(len(compressedData)))
				stream.Write(compressedData)
				return stream
			},
			description: "Should succeed with valid compressed payload",
		},
	}

	runStreamHandlerTests(t, tests, func() *Client {
		client := newTestClient(make(map[uint16]*Session))
		client.sessions[1] = &Session{id: 1, callbacks: &SessionCallbacks{}}
		return client
	}, func(c *Client, stream *Stream) {
		c.onMsgPayload(stream)
	})
}

// TestOnMsgStatusErrorPaths tests error handling in onMsgStatus message handler
func TestOnMsgStatusErrorPaths(t *testing.T) {
	tests := []streamHandlerTest{
		{
			name: "empty stream",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			description: "Should fail when stream is empty",
		},
		{
			name: "sessionId only",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				return stream
			},
			description: "Should fail when messageId is missing",
		},
		{
			name: "missing nonce field",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)   // sessionId
				stream.WriteUint32(42)  // messageId
				stream.WriteByte(1)     // status
				stream.WriteUint16(100) // size
				return stream
			},
			description: "Should fail when nonce field is missing",
		},
		{
			name: "valid complete message",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)   // sessionId
				stream.WriteUint32(42)  // messageId
				stream.WriteByte(1)     // status
				stream.WriteUint16(100) // size
				stream.WriteUint32(0)   // nonce
				return stream
			},
			description: "Should succeed with valid complete message",
		},
	}

	runStreamHandlerTests(t, tests, func() *Client {
		client := newTestClient(make(map[uint16]*Session))
		client.sessions[1] = &Session{id: 1, callbacks: &SessionCallbacks{}}
		return client
	}, func(c *Client, stream *Stream) {
		c.onMsgStatus(stream)
	})
}

// TestOnMsgSessionStatusErrorPaths tests error handling in onMsgSessionStatus handler
func TestOnMsgSessionStatusErrorPaths(t *testing.T) {
	tests := []streamHandlerTest{
		{
			name: "empty stream",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			description: "Should fail when stream is empty",
		},
		{
			name: "sessionId only",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				return stream
			},
			description: "Should fail when status is missing",
		},
		{
			name: "valid message with status 1",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				stream.WriteByte(1)   // status: created
				return stream
			},
			description: "Should handle status 1 (created)",
		},
		{
			name: "valid message with status 3",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				stream.WriteByte(3)   // status: destroyed
				return stream
			},
			description: "Should handle status 3 (destroyed)",
		},
	}

	runStreamHandlerTests(t, tests, func() *Client {
		return newTestClient(make(map[uint16]*Session))
	}, func(c *Client, stream *Stream) {
		c.onMsgSessionStatus(stream)
	})
}

// TestOnMsgReqVariableLeaseErrorPaths tests error handling in onMsgReqVariableLease
func TestOnMsgReqVariableLeaseErrorPaths(t *testing.T) {
	tests := []streamHandlerTest{
		{
			name: "empty stream",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			description: "Should fail when stream is empty",
		},
		{
			name: "sessionId only",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				return stream
			},
			description: "Should fail when tunnels count is missing",
		},
		{
			name: "valid message with zero tunnels",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				stream.WriteByte(0)   // tunnels count = 0
				return stream
			},
			description: "Should succeed with zero tunnels",
		},
		{
			name: "valid message with one complete tunnel",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				stream.WriteByte(1)   // tunnels count = 1
				// Write lease data (tunnelId + routerIdentHash + expiration)
				stream.WriteUint32(12345)              // tunnelId
				stream.Write(make([]byte, 32))         // routerIdentHash (32 bytes)
				stream.WriteUint64(uint64(1700000000)) // expiration timestamp
				return stream
			},
			description: "Should succeed with one complete tunnel",
		},
	}

	runStreamHandlerTests(t, tests, func() *Client {
		return newTestClient(make(map[uint16]*Session))
	}, func(c *Client, stream *Stream) {
		c.onMsgReqVariableLease(stream)
	})
}

// TestOnMsgHostReplyErrorPaths tests error handling in onMsgHostReply handler
func TestOnMsgHostReplyErrorPaths(t *testing.T) {
	tests := []streamHandlerTest{
		{
			name: "empty stream",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			setupClient: func(c *Client) {},
			description: "Should fail when stream is empty",
		},
		{
			name: "sessionId only",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId
				return stream
			},
			setupClient: func(c *Client) {},
			description: "Should fail when requestId is missing",
		},
		{
			name: "lookup failed with result code 1",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)  // sessionId
				stream.WriteUint32(42) // requestId
				stream.WriteByte(1)    // result: lookup failed
				return stream
			},
			setupClient: func(c *Client) {
				sess := &Session{
					id:        1,
					callbacks: &SessionCallbacks{},
				}
				c.sessions[1] = sess
				c.lookupReq[42] = LookupEntry{address: "test.i2p"}
			},
			description: "Should handle lookup failure (result code 1)",
		},
		{
			name: "session not found",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(999) // Non-existent sessionId
				stream.WriteUint32(42)  // requestId
				stream.WriteByte(1)     // result: lookup failed
				return stream
			},
			setupClient: func(c *Client) {
				c.lookupReq[42] = LookupEntry{address: "test.i2p"}
			},
			description: "Should fail when session doesn't exist",
		},
		{
			name: "lookup entry not found",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)  // sessionId
				stream.WriteUint32(99) // Non-existent requestId
				stream.WriteByte(1)    // result: lookup failed
				return stream
			},
			setupClient: func(c *Client) {
				sess := &Session{
					id:        1,
					callbacks: &SessionCallbacks{},
				}
				c.sessions[1] = sess
				// No lookup entry for requestId 99
			},
			description: "Should warn when lookup entry not found",
		},
	}

	runStreamHandlerTests(t, tests, func() *Client {
		client := newTestClient(make(map[uint16]*Session))
		client.lookupReq = make(map[uint32]LookupEntry)
		client.crypto = NewCrypto()
		return client
	}, func(c *Client, stream *Stream) {
		c.onMsgHostReply(stream)
	})
}

// TestTcpConnectErrorPaths tests error handling in tcp.Connect function
func TestTcpConnectErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantError   bool
		description string
	}{
		{
			name:        "invalid hostname",
			address:     "this-host-does-not-exist-12345.invalid:7654",
			wantError:   true,
			description: "Should fail with invalid hostname",
		},
		{
			name:        "invalid port number",
			address:     "127.0.0.1:999999",
			wantError:   true,
			description: "Should fail with invalid port number",
		},
		{
			name:        "malformed address",
			address:     "not-an-address",
			wantError:   true,
			description: "Should fail with malformed address",
		},
		{
			name:        "connection refused - likely no listener",
			address:     "127.0.0.1:19999",
			wantError:   true,
			description: "Should fail when connection is refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &Tcp{}
			// Set address manually for testing
			addr, resolveErr := net.ResolveTCPAddr("tcp", tt.address)
			if resolveErr != nil && tt.wantError {
				t.Logf("Got expected resolve error: %v", resolveErr)
				return
			}
			tcp.address = addr

			err := tcp.Connect()

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none for: %s", tt.description)
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
