package go_i2cp

import (
	"context"
	"testing"
)

func TestClient(t *testing.T) {
	client := NewClient(nil)
	client.Connect(context.Background())
	client.Disconnect()
}

func TestClient_CreateSession(t *testing.T) {
	client := NewClient(nil)

	err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(client, SessionCallbacks{
		OnDestination: func(session *Session, requestId uint32, address string, dest *Destination) {
		},
		OnStatus: func(session *Session, status SessionStatus) {
		},
		OnMessage: func(session *Session, protocol uint8, srcPort, destPort uint16, payload *Stream) {
		},
	})
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "test-i2cp")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
	session.config.destination, err = NewDestination(client.crypto) // FromBase64("r2zbc34IQSzOIF4N0enKf0xXkJKgsj9yTGGspRnstKZf~4UoAljZOW5aFZywGo-NlaXwt~tIyj4NC0Til0vl1D5N9ip7OMYUCajNNgiXEH~FN33yl-AcJbeTlB-FychSmVfYciTQj6yd19~6wICwkdpy6AYo90bAejSVGpvtFeP5P2pnSwPmcB8m79wyq~C2XjQCe5UcBxnfYolWKgr3uDFrgbhqBVCCkO7zTiARwOWZLVOvZsvKZR4WvYAmQI6CQaxnmT5n1FKO6NBb-HOxVw4onERq86Sc6EQ5d48719Yk-73wq1Mxmr7Y2UwmL~FCnY33rT1FJY2KzUENICL1uEuiVmr9N924CT9RbtldOUUcXmM1gaHlPS40-Hz4AvPxFXHynbyySktN3hBLPwfwhyIQw95ezSNuiBB0xPcujazCw02103n2CO-59rMDmWpttLjpLMggP9IwsAPa9FVLnBqfuCn3NrC4fia50RDwfR41AD1GOOWiUT0avYzbbOdsAAAA")
	if err != nil {
		t.Fatal(err)
	}
	err = client.CreateSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	client.Disconnect()
}
