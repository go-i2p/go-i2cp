package go_i2cp

import "testing"

// TestOnMsgReceiveMessageBegin tests the deprecated ReceiveMessageBegin handler
func TestOnMsgReceiveMessageBegin(t *testing.T) {
	client := setupTestClient()
	stream := NewStream(make([]byte, 6))
	stream.WriteUint16(1)
	stream.WriteUint32(12345)
	stream.Seek(0, 0)
	client.onMsgReceiveMessageBegin(stream)
}

// TestOnMsgReceiveMessageEnd tests the deprecated ReceiveMessageEnd handler
func TestOnMsgReceiveMessageEnd(t *testing.T) {
	client := setupTestClient()
	stream := NewStream(make([]byte, 6))
	stream.WriteUint16(1)
	stream.WriteUint32(67890)
	stream.Seek(0, 0)
	client.onMsgReceiveMessageEnd(stream)
}

// TestOnMsgRequestLeaseSet tests the deprecated RequestLeaseSet handler
func TestOnMsgRequestLeaseSet(t *testing.T) {
	client := setupTestClient()
	stream := NewStream(make([]byte, 3))
	stream.WriteUint16(1)
	stream.WriteByte(3)
	stream.Seek(0, 0)
	client.onMsgRequestLeaseSet(stream)
}

// TestOnMsgReportAbuse tests the deprecated ReportAbuse handler
func TestOnMsgReportAbuse(t *testing.T) {
	client := setupTestClient()
	stream := NewStream(make([]byte, 0))
	client.onMsgReportAbuse(stream)
}

// TestOnMsgBandwidthLimits tests the complete BandwidthLimits handler
func TestOnMsgBandwidthLimits(t *testing.T) {
	client := setupTestClient()
	stream := NewStream(make([]byte, 16*4))
	for i := 0; i < 16; i++ {
		stream.WriteUint32(uint32((i + 1) * 1000))
	}
	stream.Seek(0, 0)
	client.onMsgBandwidthLimit(stream)
}

// TestOnMessage_DeprecatedHandlers tests message routing
func TestOnMessage_DeprecatedHandlers(t *testing.T) {
	client := setupTestClient()

	stream1 := NewStream(make([]byte, 6))
	stream1.WriteUint16(1)
	stream1.WriteUint32(12345)
	stream1.Seek(0, 0)
	client.onMessage(I2CP_MSG_RECEIVE_MESSAGE_BEGIN, stream1)

	stream2 := NewStream(make([]byte, 6))
	stream2.WriteUint16(2)
	stream2.WriteUint32(67890)
	stream2.Seek(0, 0)
	client.onMessage(I2CP_MSG_RECEIVE_MESSAGE_END, stream2)

	stream3 := NewStream(make([]byte, 3))
	stream3.WriteUint16(3)
	stream3.WriteByte(4)
	stream3.Seek(0, 0)
	client.onMessage(I2CP_MSG_REQUEST_LEASESET, stream3)

	stream4 := NewStream(make([]byte, 0))
	client.onMessage(I2CP_MSG_REPORT_ABUSE, stream4)
}
