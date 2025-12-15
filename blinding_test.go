package go_i2cp

import (
	"sync"
	"testing"
	"time"
)

// TestSession_BlindingGettersSetters tests the blinding field getter/setter methods
// per I2CP specification 0.9.43+
func TestSession_BlindingGettersSetters(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	// Test initial state (blinding disabled)
	if session.BlindingScheme() != 0 {
		t.Errorf("Expected initial blinding scheme 0, got %d", session.BlindingScheme())
	}
	if session.BlindingFlags() != 0 {
		t.Errorf("Expected initial blinding flags 0, got %d", session.BlindingFlags())
	}
	if session.BlindingParams() != nil {
		t.Errorf("Expected initial blinding params nil, got %v", session.BlindingParams())
	}
	if session.IsBlindingEnabled() {
		t.Error("Expected blinding to be disabled initially")
	}

	// Test SetBlindingScheme
	session.SetBlindingScheme(1)
	if scheme := session.BlindingScheme(); scheme != 1 {
		t.Errorf("Expected blinding scheme 1, got %d", scheme)
	}
	if !session.IsBlindingEnabled() {
		t.Error("Expected blinding to be enabled after setting scheme")
	}

	// Test SetBlindingFlags
	session.SetBlindingFlags(0x0002)
	if flags := session.BlindingFlags(); flags != 0x0002 {
		t.Errorf("Expected blinding flags 0x0002, got 0x%04x", flags)
	}

	// Test SetBlindingParams
	testParams := []byte{0x01, 0x02, 0x03, 0x04}
	session.SetBlindingParams(testParams)
	params := session.BlindingParams()
	if len(params) != len(testParams) {
		t.Errorf("Expected params length %d, got %d", len(testParams), len(params))
	}
	for i := range testParams {
		if params[i] != testParams[i] {
			t.Errorf("Expected params[%d] = 0x%02x, got 0x%02x", i, testParams[i], params[i])
		}
	}

	// Verify params are copied (not same slice)
	params[0] = 0xFF
	if session.BlindingParams()[0] == 0xFF {
		t.Error("BlindingParams should return a copy, not the original slice")
	}

	// Test SetBlindingParams with nil
	session.SetBlindingParams(nil)
	if session.BlindingParams() != nil {
		t.Error("Expected blinding params to be nil after setting to nil")
	}

	// Test ClearBlinding
	session.SetBlindingScheme(5)
	session.SetBlindingFlags(0x1234)
	session.SetBlindingParams([]byte{0xAA, 0xBB})
	session.ClearBlinding()

	if session.BlindingScheme() != 0 {
		t.Errorf("Expected blinding scheme 0 after clear, got %d", session.BlindingScheme())
	}
	if session.BlindingFlags() != 0 {
		t.Errorf("Expected blinding flags 0 after clear, got %d", session.BlindingFlags())
	}
	if session.BlindingParams() != nil {
		t.Errorf("Expected blinding params nil after clear, got %v", session.BlindingParams())
	}
	if session.IsBlindingEnabled() {
		t.Error("Expected blinding to be disabled after clear")
	}
}

// TestSession_BlindingConcurrency tests thread-safety of blinding operations
// per I2CP specification 0.9.43+
func TestSession_BlindingConcurrency(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingScheme(uint16(i % 10))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingFlags(uint16(i % 100))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingParams([]byte{byte(i), byte(i + 1)})
		}
	}()

	// Concurrent reads
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingScheme()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingFlags()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingParams()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.IsBlindingEnabled()
		}
	}()

	wg.Wait()
	// If we reach here without race detector errors, test passes
}

// TestDispatchBlindingInfo tests the blinding info dispatch method
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo(t *testing.T) {
	tests := []struct {
		name           string
		setupCallback  func(*Session)
		blindingScheme uint16
		blindingFlags  uint16
		blindingParams []byte
		expectDispatch bool
	}{
		{
			name: "successful dispatch",
			setupCallback: func(s *Session) {
				s.callbacks = &SessionCallbacks{
					OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
						if scheme != 1 {
							t.Errorf("Expected scheme 1, got %d", scheme)
						}
						if flags != 0x0002 {
							t.Errorf("Expected flags 0x0002, got 0x%04x", flags)
						}
						if len(params) != 4 {
							t.Errorf("Expected params length 4, got %d", len(params))
						}
					},
				}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01, 0x02, 0x03, 0x04},
			expectDispatch: true,
		},
		{
			name: "no callback registered",
			setupCallback: func(s *Session) {
				s.callbacks = &SessionCallbacks{}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01, 0x02},
			expectDispatch: false,
		},
		{
			name: "nil callbacks",
			setupCallback: func(s *Session) {
				s.callbacks = nil
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01},
			expectDispatch: false,
		},
		{
			name: "closed session",
			setupCallback: func(s *Session) {
				s.closed = true
				s.callbacks = &SessionCallbacks{
					OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
						t.Error("Callback should not be called for closed session")
					},
				}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01},
			expectDispatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}
			session := newSession(client, SessionCallbacks{})
			tt.setupCallback(session)

			session.dispatchBlindingInfo(tt.blindingScheme, tt.blindingFlags, tt.blindingParams)

			// Give async callback time to execute
			time.Sleep(10 * time.Millisecond)
		})
	}
}

// TestDispatchBlindingInfo_CallbackPanic tests panic recovery in blinding callback
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo_CallbackPanic(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{
		OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
			panic("intentional test panic")
		},
	})

	// Should not panic - panic should be recovered
	session.dispatchBlindingInfo(1, 0x0002, []byte{0x01, 0x02})

	// Give async callback time to execute
	time.Sleep(10 * time.Millisecond)

	// If we reach here without panic propagating, test passes
}

// TestDispatchBlindingInfo_AsyncCallback tests asynchronous callback execution
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo_AsyncCallback(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	callbackCalled := make(chan bool, 1)
	session := newSession(client, SessionCallbacks{
		OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
			time.Sleep(5 * time.Millisecond) // Simulate work
			callbackCalled <- true
		},
	})
	session.syncCallbacks = false // Enable async mode

	session.dispatchBlindingInfo(1, 0x0002, []byte{0x01, 0x02})

	// Dispatch should return immediately in async mode
	select {
	case <-callbackCalled:
		t.Error("Callback should not have completed yet (async mode)")
	case <-time.After(1 * time.Millisecond):
		// Expected - callback still running
	}

	// Wait for callback to complete
	select {
	case <-callbackCalled:
		// Expected - callback completed
	case <-time.After(100 * time.Millisecond):
		t.Error("Callback did not complete within timeout")
	}
}

// TestOnMsgBlindingInfo tests the BlindingInfoMessage handler
// per I2CP specification 0.9.43+
func TestOnMsgBlindingInfo(t *testing.T) {
	tests := []struct {
		name            string
		sessionId       uint16
		authScheme      uint8
		flags           uint16
		params          []byte
		sessionExists   bool
		expectError     bool
		validateSession func(*testing.T, *Session)
		callbackCalled  *bool
	}{
		{
			name:          "successful blinding info",
			sessionId:     1,
			authScheme:    1,
			flags:         0x0002,
			params:        []byte{0x01, 0x02, 0x03, 0x04},
			sessionExists: true,
			expectError:   false,
			validateSession: func(t *testing.T, s *Session) {
				if scheme := s.BlindingScheme(); scheme != 1 {
					t.Errorf("Expected blinding scheme 1, got %d", scheme)
				}
				if flags := s.BlindingFlags(); flags != 0x0002 {
					t.Errorf("Expected blinding flags 0x0002, got 0x%04x", flags)
				}
				params := s.BlindingParams()
				if len(params) != 4 {
					t.Errorf("Expected params length 4, got %d", len(params))
				}
				if !s.IsBlindingEnabled() {
					t.Error("Expected blinding to be enabled")
				}
			},
		},
		{
			name:          "blinding with empty params",
			sessionId:     1,
			authScheme:    2,
			flags:         0x0000,
			params:        []byte{},
			sessionExists: true,
			expectError:   false,
			validateSession: func(t *testing.T, s *Session) {
				if scheme := s.BlindingScheme(); scheme != 2 {
					t.Errorf("Expected blinding scheme 2, got %d", scheme)
				}
				params := s.BlindingParams()
				if len(params) != 0 {
					t.Errorf("Expected empty params, got length %d", len(params))
				}
			},
		},
		{
			name:          "unknown session",
			sessionId:     999,
			authScheme:    1,
			flags:         0x0002,
			params:        []byte{0x01},
			sessionExists: false,
			expectError:   true,
		},
		{
			name:           "callback dispatched",
			sessionId:      1,
			authScheme:     1,
			flags:          0x0002,
			params:         []byte{0xAA, 0xBB},
			sessionExists:  true,
			expectError:    false,
			callbackCalled: new(bool),
			validateSession: func(t *testing.T, s *Session) {
				// Callback validation happens in setupCallback
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}

			var session *Session
			if tt.sessionExists {
				callbacks := SessionCallbacks{}
				if tt.callbackCalled != nil {
					callbacks.OnBlindingInfo = func(s *Session, scheme, flags uint16, params []byte) {
						*tt.callbackCalled = true
						if scheme != uint16(tt.authScheme) {
							t.Errorf("Callback: expected scheme %d, got %d", tt.authScheme, scheme)
						}
						if flags != tt.flags {
							t.Errorf("Callback: expected flags 0x%04x, got 0x%04x", tt.flags, flags)
						}
						if len(params) != len(tt.params) {
							t.Errorf("Callback: expected params length %d, got %d", len(tt.params), len(params))
						}
					}
				}
				session = newSession(client, callbacks)
				session.id = tt.sessionId
				client.sessions[tt.sessionId] = session
			}

			// Create message stream
			stream := NewStream(make([]byte, 0, 256))
			stream.WriteUint16(tt.sessionId)
			stream.WriteByte(tt.authScheme)
			stream.WriteUint16(tt.flags)
			stream.WriteUint16(uint16(len(tt.params)))
			stream.Write(tt.params)

			// Reset stream position for reading
			stream = NewStream(stream.Bytes())

			// Call handler
			client.onMsgBlindingInfo(stream)

			// Validate session state
			if tt.sessionExists && tt.validateSession != nil && !tt.expectError {
				tt.validateSession(t, session)
			}

			// Validate callback was called
			if tt.callbackCalled != nil {
				time.Sleep(10 * time.Millisecond) // Allow async callback to execute
				if !*tt.callbackCalled {
					t.Error("Expected callback to be called")
				}
			}
		})
	}
}

// TestOnMsgBlindingInfo_InvalidData tests error handling for malformed BlindingInfo messages
// per I2CP specification 0.9.43+
func TestOnMsgBlindingInfo_InvalidData(t *testing.T) {
	tests := []struct {
		name        string
		setupStream func() *Stream
	}{
		{
			name: "truncated session id",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteByte(0x01) // Only 1 byte instead of 2 for session ID
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated auth scheme",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1) // Session ID
				// Missing auth scheme
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated flags",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1) // Session ID
				stream.WriteByte(1)   // Auth scheme
				// Missing flags
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated param length",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1)      // Session ID
				stream.WriteByte(1)        // Auth scheme
				stream.WriteUint16(0x0002) // Flags
				// Missing param length
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated params",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1)            // Session ID
				stream.WriteByte(1)              // Auth scheme
				stream.WriteUint16(0x0002)       // Flags
				stream.WriteUint16(10)           // Param length = 10
				stream.Write([]byte{0x01, 0x02}) // Only 2 bytes instead of 10
				return NewStream(stream.Bytes())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}

			// Create session
			session := newSession(client, SessionCallbacks{
				OnBlindingInfo: func(s *Session, scheme, flags uint16, params []byte) {
					t.Error("Callback should not be called for invalid data")
				},
			})
			session.id = 1
			client.sessions[1] = session

			// Call handler with malformed stream
			stream := tt.setupStream()
			client.onMsgBlindingInfo(stream)

			// If we reach here without panic, error handling worked
			// Callback should not have been called (verified above)
		})
	}
}
