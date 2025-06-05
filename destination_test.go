package go_i2cp

import "testing"

func TestRandomDestination(t *testing.T) {
	var destOne, destTwo *Destination
	var err error
	crypto := NewCrypto()
	destOne, err = NewDestination(crypto)
	var stream = NewStream(make([]byte, 4096))
	destOne.WriteToStream(stream)
	if err != nil {
		t.Fatalf("Could not create first test destination with error %s", err.Error())
	}
	destTwo, err = NewDestination(crypto)
	if err != nil {
		t.Fatalf("Could not create second test destination with error %s", err.Error())
	}
	if destOne.b32 == destTwo.b32 {
		t.Fatal("Random destOne == random destTwo")
	}
}

func TestNewDestinationFromMessage(t *testing.T) {
	stream := NewStream(make([]byte, 0, 4096))
	crypto := NewCrypto()
	randDest, err := NewDestination(crypto)
	if err != nil {
		t.Fatal("Could not create random destination.")
	}
	initialB32 := randDest.b32
	randDest.WriteToMessage(stream)
	secDest, err := NewDestinationFromMessage(stream, crypto)
	if err != nil {
		t.Fatalf("Failed to create destination from message: '%s'", err.Error())
	}
	finalB32 := secDest.b32
	if initialB32 != finalB32 {
		t.Fatalf("Recreated destination base32 addresses do not match %s != %s", initialB32, finalB32)
	}
}

func TestNewDestinationFromBase64(t *testing.T) {
	crypto := NewCrypto()
	randDest, err := NewDestination(crypto)
	if err != nil {
		t.Fatal("Could not create random destination.")
	}
	initialB64 := randDest.b64
	secDest, err := NewDestinationFromBase64(initialB64, crypto)
	if err != nil {
		t.Fatalf("Failed to create destination from message: '%s'", err.Error())
	}
	finalB64 := secDest.b64
	if initialB64 != finalB64 {
		t.Fatalf("Recreated destination base64 addresses do not match %s != %s", initialB64, finalB64)
	}
}
