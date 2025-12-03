package go_i2cp

// getMessageTypeName returns a human-readable name for I2CP message types
// This is useful for wire-level debugging and logging
func getMessageTypeName(msgType uint8) string {
	switch msgType {
	case I2CP_MSG_CREATE_SESSION:
		return "CreateSession"
	case I2CP_MSG_RECONFIGURE_SESSION:
		return "ReconfigureSession"
	case I2CP_MSG_DESTROY_SESSION:
		return "DestroySession"
	case I2CP_MSG_SEND_MESSAGE:
		return "SendMessage"
	case I2CP_MSG_RECEIVE_MESSAGE_BEGIN:
		return "ReceiveMessageBegin (deprecated)"
	case I2CP_MSG_RECEIVE_MESSAGE_END:
		return "ReceiveMessageEnd (deprecated)"
	case I2CP_MSG_SET_DATE:
		return "SetDate"
	case I2CP_MSG_REQUEST_LEASESET:
		return "RequestLeaseSet (deprecated)"
	case I2CP_MSG_SESSION_STATUS:
		return "SessionStatus"
	case I2CP_MSG_MESSAGE_STATUS:
		return "MessageStatus"
	case I2CP_MSG_GET_BANDWIDTH_LIMITS:
		return "GetBandwidthLimits"
	case I2CP_MSG_BANDWIDTH_LIMITS:
		return "BandwidthLimits"
	case I2CP_MSG_DISCONNECT:
		return "Disconnect"
	case I2CP_MSG_REPORT_ABUSE:
		return "ReportAbuse (deprecated)"
	case I2CP_MSG_PAYLOAD_MESSAGE:
		return "PayloadMessage"
	case I2CP_MSG_GET_DATE:
		return "GetDate"
	case I2CP_MSG_DEST_LOOKUP:
		return "DestLookup (deprecated)"
	case I2CP_MSG_DEST_REPLY:
		return "DestReply (deprecated)"
	case I2CP_MSG_CREATE_LEASE_SET:
		return "CreateLeaseSet"
	case I2CP_MSG_SEND_MESSAGE_EXPIRES:
		return "SendMessageExpires"
	case I2CP_MSG_REQUEST_VARIABLE_LEASESET:
		return "RequestVariableLeaseSet"
	case I2CP_MSG_HOST_LOOKUP:
		return "HostLookup"
	case I2CP_MSG_HOST_REPLY:
		return "HostReply"
	case I2CP_MSG_CREATE_LEASE_SET2:
		return "CreateLeaseSet2"
	case I2CP_MSG_BLINDING_INFO:
		return "BlindingInfo"
	case I2CP_MSG_ANY:
		return "ANY (receive any type)"
	default:
		return "Unknown"
	}
}
