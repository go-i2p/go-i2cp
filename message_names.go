package go_i2cp

var (
	sessionManagementNames = map[uint8]string{
		I2CP_MSG_CREATE_SESSION:      "CreateSession",
		I2CP_MSG_RECONFIGURE_SESSION: "ReconfigureSession",
		I2CP_MSG_DESTROY_SESSION:     "DestroySession",
		I2CP_MSG_SESSION_STATUS:      "SessionStatus",
		I2CP_MSG_DISCONNECT:          "Disconnect",
		I2CP_MSG_ANY:                 "ANY (receive any type)",
	}

	dataTransferNames = map[uint8]string{
		I2CP_MSG_SEND_MESSAGE:          "SendMessage",
		I2CP_MSG_SEND_MESSAGE_EXPIRES:  "SendMessageExpires",
		I2CP_MSG_PAYLOAD_MESSAGE:       "PayloadMessage",
		I2CP_MSG_MESSAGE_STATUS:        "MessageStatus",
		I2CP_MSG_RECEIVE_MESSAGE_BEGIN: "ReceiveMessageBegin (deprecated)",
		I2CP_MSG_RECEIVE_MESSAGE_END:   "ReceiveMessageEnd (deprecated)",
		I2CP_MSG_GET_BANDWIDTH_LIMITS:  "GetBandwidthLimits",
		I2CP_MSG_BANDWIDTH_LIMITS:      "BandwidthLimits",
		I2CP_MSG_REPORT_ABUSE:          "ReportAbuse (deprecated)",
	}

	destinationLookupNames = map[uint8]string{
		I2CP_MSG_DEST_LOOKUP: "DestLookup (deprecated)",
		I2CP_MSG_DEST_REPLY:  "DestReply (deprecated)",
		I2CP_MSG_HOST_LOOKUP: "HostLookup",
		I2CP_MSG_HOST_REPLY:  "HostReply",
	}

	leaseSetNames = map[uint8]string{
		I2CP_MSG_CREATE_LEASE_SET:          "CreateLeaseSet",
		I2CP_MSG_CREATE_LEASE_SET2:         "CreateLeaseSet2",
		I2CP_MSG_REQUEST_LEASESET:          "RequestLeaseSet (deprecated)",
		I2CP_MSG_REQUEST_VARIABLE_LEASESET: "RequestVariableLeaseSet",
		I2CP_MSG_BLINDING_INFO:             "BlindingInfo",
		I2CP_MSG_SET_DATE:                  "SetDate",
		I2CP_MSG_GET_DATE:                  "GetDate",
	}
)

// getMessageTypeName returns a human-readable name for I2CP message types.
// This is useful for wire-level debugging and logging.
func getMessageTypeName(msgType uint8) string {
	if name := getSessionManagementMessageName(msgType); name != "" {
		return name
	}
	if name := getDataTransferMessageName(msgType); name != "" {
		return name
	}
	if name := getDestinationLookupMessageName(msgType); name != "" {
		return name
	}
	if name := getLeaseSetMessageName(msgType); name != "" {
		return name
	}
	return "Unknown"
}

// getSessionManagementMessageName returns names for session lifecycle messages.
func getSessionManagementMessageName(msgType uint8) string {
	if name, ok := sessionManagementNames[msgType]; ok {
		return name
	}
	return ""
}

// getDataTransferMessageName returns names for data transfer and messaging types.
func getDataTransferMessageName(msgType uint8) string {
	if name, ok := dataTransferNames[msgType]; ok {
		return name
	}
	return ""
}

// getDestinationLookupMessageName returns names for destination and host lookup messages.
func getDestinationLookupMessageName(msgType uint8) string {
	if name, ok := destinationLookupNames[msgType]; ok {
		return name
	}
	return ""
}

// getLeaseSetMessageName returns names for LeaseSet creation and management messages.
func getLeaseSetMessageName(msgType uint8) string {
	if name, ok := leaseSetNames[msgType]; ok {
		return name
	}
	return ""
}
