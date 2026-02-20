package go_i2cp

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"
)

// Benchmark Message Throughput
// Tests the performance of core I2CP message serialization and deserialization operations

func BenchmarkStream_WriteUint16(b *testing.B) {
	stream := NewStream(make([]byte, 0, 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint16(uint16(i))
	}
}

func BenchmarkStream_ReadUint16(b *testing.B) {
	// Pre-populate stream with uint16 values
	stream := NewStream(make([]byte, 0, b.N*2))
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint16(uint16(i))
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = stream.ReadUint16()
	}
}

func BenchmarkStream_WriteUint32(b *testing.B) {
	stream := NewStream(make([]byte, 0, 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint32(uint32(i))
	}
}

func BenchmarkStream_ReadUint32(b *testing.B) {
	// Pre-populate stream with uint32 values
	stream := NewStream(make([]byte, 0, b.N*4))
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint32(uint32(i))
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = stream.ReadUint32()
	}
}

func BenchmarkStream_WriteUint64(b *testing.B) {
	stream := NewStream(make([]byte, 0, 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint64(uint64(i))
	}
}

func BenchmarkStream_ReadUint64(b *testing.B) {
	// Pre-populate stream with uint64 values
	stream := NewStream(make([]byte, 0, b.N*8))
	for i := 0; i < b.N; i++ {
		_ = stream.WriteUint64(uint64(i))
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = stream.ReadUint64()
	}
}

func BenchmarkStream_WriteLenPrefixedString(b *testing.B) {
	stream := NewStream(make([]byte, 0, 1024))
	testString := "test.i2p.example.destination.b32"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = stream.WriteLenPrefixedString(testString)
	}
}

func BenchmarkStream_WriteMapping(b *testing.B) {
	stream := NewStream(make([]byte, 0, 1024))
	mapping := map[string]string{
		"inbound.length":    "3",
		"outbound.length":   "3",
		"inbound.quantity":  "2",
		"outbound.quantity": "2",
		"i2cp.fastReceive":  "true",
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = stream.WriteMapping(mapping)
	}
}

func BenchmarkStream_ReadMapping(b *testing.B) {
	// Pre-populate stream with mappings
	mapping := map[string]string{
		"inbound.length":    "3",
		"outbound.length":   "3",
		"inbound.quantity":  "2",
		"outbound.quantity": "2",
		"i2cp.fastReceive":  "true",
	}

	streams := make([]*Stream, b.N)
	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 256))
		_ = stream.WriteMapping(mapping)
		streams[i] = stream
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = streams[i].ReadMapping()
	}
}

// Benchmark Crypto Operations
// Tests the performance of modern cryptographic primitives

func BenchmarkEd25519_KeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			b.Fatal(err)
		}
		// Ensure key is used to prevent optimization
		_ = kp
	}
}

func BenchmarkEd25519_Sign(b *testing.B) {
	kp, err := NewEd25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kp.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	kp, err := NewEd25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		b.Fatal(err)
	}

	signature, err := kp.Sign(message)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verified := kp.Verify(message, signature)
		if !verified {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkX25519_KeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp, err := NewX25519KeyPair()
		if err != nil {
			b.Fatal(err)
		}
		// Ensure key is used to prevent optimization
		_ = kp
	}
}

func BenchmarkX25519_SharedSecret(b *testing.B) {
	kp1, err := NewX25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	kp2, err := NewX25519KeyPair()
	if err != nil {
		b.Fatal(err)
	}

	peerPubKey := kp2.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kp1.GenerateSharedSecret(peerPubKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Poly1305_Encrypt(b *testing.B) {
	cipher, err := NewChaCha20Poly1305Cipher()
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Poly1305_Decrypt(b *testing.B) {
	cipher, err := NewChaCha20Poly1305Cipher()
	if err != nil {
		b.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatal(err)
	}

	ciphertext, err := cipher.Encrypt(plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Decrypt(ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDSA_KeyGeneration(b *testing.B) {
	crypto := NewCrypto()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := crypto.SignatureKeygen(ED25519_SHA256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDSA_Sign(b *testing.B) {
	crypto := NewCrypto()
	kp, err := crypto.SignatureKeygen(ED25519_SHA256)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(message)
		err := kp.ed25519KeyPair.SignStream(stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDSA_Verify(b *testing.B) {
	crypto := NewCrypto()
	kp, err := crypto.SignatureKeygen(ED25519_SHA256)
	if err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		b.Fatal(err)
	}

	// Sign the message
	stream := NewStream(message)
	err = kp.ed25519KeyPair.SignStream(stream)
	if err != nil {
		b.Fatal(err)
	}
	signedStream := stream.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyStream := NewStream(signedStream)
		_, err := kp.ed25519KeyPair.VerifyStream(verifyStream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark Serialization/Deserialization
// Tests the performance of I2CP data structure encoding/decoding

func BenchmarkDestination_Serialization(b *testing.B) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 512))
		err := dest.WriteToStream(stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDestination_Deserialization(b *testing.B) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-serialize destination
	stream := NewStream(make([]byte, 0, 512))
	err = dest.WriteToStream(stream)
	if err != nil {
		b.Fatal(err)
	}
	serialized := stream.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(serialized)
		_, err := NewDestinationFromStream(stream, crypto)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCertificate_Serialization(b *testing.B) {
	cert := NewCertificate(CERTIFICATE_NULL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 128))
		err := WriteCertificateToStream(cert, stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCertificate_Deserialization(b *testing.B) {
	cert := NewCertificate(CERTIFICATE_NULL)

	// Pre-serialize certificate
	stream := NewStream(make([]byte, 0, 128))
	err := WriteCertificateToStream(cert, stream)
	if err != nil {
		b.Fatal(err)
	}
	serialized := stream.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(serialized)
		_, err := NewCertificateFromStream(stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark Concurrent Sessions
// Tests the performance of session management under concurrent load

func BenchmarkSession_Creation(b *testing.B) {
	crypto := NewCrypto()
	client := &Client{
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess := NewSession(client, SessionCallbacks{})
		_ = sess
	}
}

func BenchmarkSession_CreationWithContext(b *testing.B) {
	crypto := NewCrypto()
	client := &Client{
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess, err := NewSessionWithContext(ctx, client, SessionCallbacks{})
		if err != nil {
			b.Fatal(err)
		}
		_ = sess
	}
}

func BenchmarkSession_ConcurrentCreation(b *testing.B) {
	crypto := NewCrypto()
	client := &Client{
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sess := NewSession(client, SessionCallbacks{})
			_ = sess
		}
	})
}

func BenchmarkClient_SessionLookup(b *testing.B) {
	crypto := NewCrypto()
	client := &Client{
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	// Pre-populate sessions
	for i := uint16(0); i < 100; i++ {
		sess := NewSession(client, SessionCallbacks{})
		sess.id = i
		client.sessions[i] = sess
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionId := uint16(i % 100)
		client.lock.Lock()
		sess := client.sessions[sessionId]
		client.lock.Unlock()
		_ = sess
	}
}

func BenchmarkCircuitBreaker_Operation(b *testing.B) {
	cb := NewCircuitBreaker(5, 10*time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.Execute(func() error {
			return nil
		})
	}
}

// Benchmark Message Construction
// Tests the performance of building complete I2CP messages

func BenchmarkMessage_CreateSession(b *testing.B) {
	crypto := NewCrypto()
	client := &Client{
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	sess := NewSession(client, SessionCallbacks{})
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatal(err)
	}
	sess.config.destination = dest

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 1024))

		// Build CreateSessionMessage structure
		_ = stream.WriteByte(I2CP_MSG_CREATE_SESSION)
		_ = sess.config.destination.WriteToStream(stream)

		options := map[string]string{
			"inbound.length":   "3",
			"outbound.length":  "3",
			"i2cp.fastReceive": "true",
		}
		_ = stream.WriteMapping(options)

		sessionDate := uint64(time.Now().Unix())
		_ = stream.WriteUint64(sessionDate)

		_ = stream.Bytes()
	}
}

func BenchmarkMessage_SendMessage(b *testing.B) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 512)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 1024))

		// Build SendMessageMessage structure
		sessionId := uint16(1)
		_ = stream.WriteUint16(sessionId)
		_ = dest.WriteToStream(stream)

		// Write payload with size prefix
		_ = stream.WriteUint32(uint32(len(payload)))
		_, _ = stream.Write(payload)

		// Write nonce
		nonce := uint32(i)
		_ = stream.WriteUint32(nonce)

		_ = stream.Bytes()
	}
}

// Benchmark Buffer Operations
// Tests the performance of underlying buffer operations

func BenchmarkBuffer_Write1KB(b *testing.B) {
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(make([]byte, 0, 1024))
		_, _ = buf.Write(data)
	}
}

func BenchmarkBuffer_Write10KB(b *testing.B) {
	data := make([]byte, 10*1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(make([]byte, 0, 10*1024))
		_, _ = buf.Write(data)
	}
}

func BenchmarkBuffer_Read1KB(b *testing.B) {
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(data)
		readBuf := make([]byte, 1024)
		_, _ = buf.Read(readBuf)
	}
}

func BenchmarkBuffer_Read10KB(b *testing.B) {
	data := make([]byte, 10*1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(data)
		readBuf := make([]byte, 10*1024)
		_, _ = buf.Read(readBuf)
	}
}
