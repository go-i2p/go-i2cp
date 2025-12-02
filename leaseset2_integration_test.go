package go_i2cp

import (
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/lease"
)

// TestOnMsgCreateLeaseSet2_Success tests successful LeaseSet2 message handling
func TestOnMsgCreateLeaseSet2_Success(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	// Create a test session with callback
	var receivedLeaseSet *LeaseSet2
	var callbackCalled bool
	var callbackMu sync.Mutex

	session := &Session{
		id:            1,
		client:        client,
		syncCallbacks: true, // Synchronous for testing
		callbacks: &SessionCallbacks{
			OnLeaseSet2: func(s *Session, ls *LeaseSet2) {
				callbackMu.Lock()
				defer callbackMu.Unlock()
				receivedLeaseSet = ls
				callbackCalled = true
			},
		},
	}

	client.lock.Lock()
	client.sessions[1] = session
	client.lock.Unlock()

	// Create test destination
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Build CreateLeaseSet2Message
	stream := NewStream(make([]byte, 0, 1024))

	// Session ID
	stream.WriteUint16(1)

	// LeaseSet2 data
	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0) // flags
	stream.WriteMapping(map[string]string{})
	stream.WriteByte(1) // 1 lease

	// Lease2
	gateway := make([]byte, 32)
	stream.Write(gateway)
	stream.WriteUint32(1000)
	stream.WriteUint32(uint32(time.Now().Add(5 * time.Minute).Unix()))

	// Signature
	signature := make([]byte, 40)
	stream.Write(signature)

	// Process message
	parseStream := NewStream(stream.Bytes())
	client.onMsgCreateLeaseSet2(parseStream)

	// Verify callback was called
	callbackMu.Lock()
	defer callbackMu.Unlock()

	if !callbackCalled {
		t.Error("OnLeaseSet2 callback was not called")
	}

	if receivedLeaseSet == nil {
		t.Fatal("Received LeaseSet2 is nil")
	}

	if receivedLeaseSet.Type() != LEASESET_TYPE_STANDARD {
		t.Errorf("Expected type %d, got %d", LEASESET_TYPE_STANDARD, receivedLeaseSet.Type())
	}

	if receivedLeaseSet.LeaseCount() != 1 {
		t.Errorf("Expected 1 lease, got %d", receivedLeaseSet.LeaseCount())
	}
}

// TestOnMsgCreateLeaseSet2_UnknownSession tests handling of unknown session
func TestOnMsgCreateLeaseSet2_UnknownSession(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	stream := NewStream(make([]byte, 0, 100))
	stream.WriteUint16(999) // Unknown session

	parseStream := NewStream(stream.Bytes())

	// Should log warning and return without panic
	client.onMsgCreateLeaseSet2(parseStream)

	// Test passes if no panic occurred
}

// TestOnMsgCreateLeaseSet2_InvalidSessionID tests error handling for invalid session ID
func TestOnMsgCreateLeaseSet2_InvalidSessionID(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	stream := NewStream(make([]byte, 0, 10))
	// Empty stream - cannot read session ID

	parseStream := NewStream(stream.Bytes())

	// Should log error and return without panic
	client.onMsgCreateLeaseSet2(parseStream)

	// Test passes if no panic occurred
}

// TestOnMsgCreateLeaseSet2_InvalidLeaseSet tests handling of invalid LeaseSet data
func TestOnMsgCreateLeaseSet2_InvalidLeaseSet(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	session := &Session{
		id:     1,
		client: client,
	}

	client.lock.Lock()
	client.sessions[1] = session
	client.lock.Unlock()

	stream := NewStream(make([]byte, 0, 100))
	stream.WriteUint16(1) // Valid session ID
	stream.WriteByte(99)  // Invalid LeaseSet type

	parseStream := NewStream(stream.Bytes())

	// Should log error and return without panic
	client.onMsgCreateLeaseSet2(parseStream)

	// Test passes if no panic occurred
}

// TestOnMsgCreateLeaseSet2_ExpiredLeaseSet tests handling of expired LeaseSet
func TestOnMsgCreateLeaseSet2_ExpiredLeaseSet(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	var receivedLeaseSet *LeaseSet2
	var callbackMu sync.Mutex

	session := &Session{
		id:            1,
		client:        client,
		syncCallbacks: true,
		callbacks: &SessionCallbacks{
			OnLeaseSet2: func(s *Session, ls *LeaseSet2) {
				callbackMu.Lock()
				defer callbackMu.Unlock()
				receivedLeaseSet = ls
			},
		},
	}

	client.lock.Lock()
	client.sessions[1] = session
	client.lock.Unlock()

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteUint16(1)
	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)

	// Expired timestamps
	stream.WriteUint32(uint32(time.Now().Add(-20 * time.Minute).Unix()))
	stream.WriteUint32(uint32(time.Now().Add(-10 * time.Minute).Unix()))

	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{})
	stream.WriteByte(0) // 0 leases

	signature := make([]byte, 40)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	client.onMsgCreateLeaseSet2(parseStream)

	// Verify callback was called despite expiration (warning only)
	callbackMu.Lock()
	defer callbackMu.Unlock()

	if receivedLeaseSet == nil {
		t.Fatal("Callback should still be called for expired LeaseSet")
	}

	if !receivedLeaseSet.IsExpired() {
		t.Error("LeaseSet should be marked as expired")
	}
}

// TestOnMsgCreateLeaseSet2_NoCallback tests behavior when no callback is registered
func TestOnMsgCreateLeaseSet2_NoCallback(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	// Session without callbacks
	session := &Session{
		id:     1,
		client: client,
	}

	client.lock.Lock()
	client.sessions[1] = session
	client.lock.Unlock()

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteUint16(1)
	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{})
	stream.WriteByte(0)

	signature := make([]byte, 40)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())

	// Should log debug message and return without panic
	client.onMsgCreateLeaseSet2(parseStream)

	// Test passes if no panic occurred
}

// TestDispatchLeaseSet2_ClosedSession tests dispatch to closed session
func TestDispatchLeaseSet2_ClosedSession(t *testing.T) {
	session := &Session{
		id:     1,
		closed: true, // Closed session
	}

	leaseSet := &LeaseSet2{
		leaseSetType: LEASESET_TYPE_STANDARD,
	}

	// Should log warning and return without panic
	session.dispatchLeaseSet2(leaseSet)

	// Test passes if no panic occurred
}

// TestDispatchLeaseSet2_CallbackPanic tests panic recovery in callback
func TestDispatchLeaseSet2_CallbackPanic(t *testing.T) {
	session := &Session{
		id:            1,
		syncCallbacks: true,
		callbacks: &SessionCallbacks{
			OnLeaseSet2: func(s *Session, ls *LeaseSet2) {
				panic("test panic in callback")
			},
		},
	}

	leaseSet := &LeaseSet2{
		leaseSetType: LEASESET_TYPE_STANDARD,
		leases:       make([]*lease.Lease2, 0),
	}

	// Should recover from panic and log error
	session.dispatchLeaseSet2(leaseSet)

	// Test passes if panic was recovered
}

// TestDispatchLeaseSet2_AsyncCallback tests asynchronous callback execution
func TestDispatchLeaseSet2_AsyncCallback(t *testing.T) {
	var callbackCalled bool
	var callbackMu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(1)

	session := &Session{
		id:            1,
		syncCallbacks: false, // Async
		callbacks: &SessionCallbacks{
			OnLeaseSet2: func(s *Session, ls *LeaseSet2) {
				callbackMu.Lock()
				callbackCalled = true
				callbackMu.Unlock()
				wg.Done()
			},
		},
	}

	leaseSet := &LeaseSet2{
		leaseSetType: LEASESET_TYPE_STANDARD,
		leases:       make([]*lease.Lease2, 2),
		expires:      uint32(time.Now().Add(10 * time.Minute).Unix()),
	}

	session.dispatchLeaseSet2(leaseSet)

	// Wait for async callback
	wg.Wait()

	callbackMu.Lock()
	defer callbackMu.Unlock()

	if !callbackCalled {
		t.Error("Async callback was not executed")
	}
}

// TestOnMsgCreateLeaseSet2_EncryptedType tests handling of encrypted LeaseSet
func TestOnMsgCreateLeaseSet2_EncryptedType(t *testing.T) {
	client := &Client{
		crypto:   NewCrypto(),
		sessions: make(map[uint16]*Session),
		lock:     sync.Mutex{},
	}

	var receivedType uint8
	var callbackMu sync.Mutex

	session := &Session{
		id:            1,
		client:        client,
		syncCallbacks: true,
		callbacks: &SessionCallbacks{
			OnLeaseSet2: func(s *Session, ls *LeaseSet2) {
				callbackMu.Lock()
				receivedType = ls.Type()
				callbackMu.Unlock()
			},
		},
	}

	client.lock.Lock()
	client.sessions[1] = session
	client.lock.Unlock()

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteUint16(1)
	stream.WriteByte(LEASESET_TYPE_ENCRYPTED)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{"encryption": "chacha20"})
	stream.WriteByte(1)

	gateway := make([]byte, 32)
	stream.Write(gateway)
	stream.WriteUint32(2000)
	stream.WriteUint32(uint32(time.Now().Add(5 * time.Minute).Unix()))

	signature := make([]byte, 40)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	client.onMsgCreateLeaseSet2(parseStream)

	callbackMu.Lock()
	defer callbackMu.Unlock()

	if receivedType != LEASESET_TYPE_ENCRYPTED {
		t.Errorf("Expected encrypted type %d, got %d", LEASESET_TYPE_ENCRYPTED, receivedType)
	}
}
