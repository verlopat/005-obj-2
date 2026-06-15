package chaincode_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogSecurityEvent(t *testing.T) {
	stub := shimtest.NewMockStub("security_logger", new(SecurityLoggerChaincode))
	stub.MockTransactionStart("tx1")

	args := [][]byte{
		[]byte("LogSecurityEvent"),
		[]byte("evt-001"),
		[]byte("asset-cloud-001"),
		[]byte("HIGH"),
		[]byte("Suspected DDoS attack"),
		[]byte("bafkreihdwdcefgh4d6idymr7gebsf6qk2ir2l2v5d5k7s3toh3q3hkplcm"),
		[]byte("abc123def456abc123def456abc123def456abc123def456abc123def456abc1"),
		[]byte("DDOS"),
		[]byte("0.97"),
		[]byte("v1.0"),
		[]byte(""),
		[]byte(time.Now().UTC().Format(time.RFC3339)),
	}

	res := stub.MockInvoke("tx1", args)
	assert.Equal(t, int32(200), res.Status)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(res.Payload, &result))
	assert.Equal(t, "evt-001", result["event_id"])
}

func TestGetSecurityEvent(t *testing.T) {
	stub := shimtest.NewMockStub("security_logger", new(SecurityLoggerChaincode))
	stub.MockTransactionStart("tx2")

	logArgs := [][]byte{
		[]byte("LogSecurityEvent"),
		[]byte("evt-002"),
		[]byte("asset-002"),
		[]byte("CRITICAL"),
		[]byte("Ransomware detected"),
		[]byte("bafkreitest000000000000000000000000000000000000000000000000000"),
		[]byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		[]byte("RANSOMWARE"),
		[]byte("0.99"),
		[]byte("v1.0"),
		[]byte(""),
		[]byte(time.Now().UTC().Format(time.RFC3339)),
	}
	stub.MockInvoke("tx2", logArgs)

	getArgs := [][]byte{[]byte("GetSecurityEvent"), []byte("evt-002")}
	res := stub.MockInvoke("tx3", getArgs)
	assert.Equal(t, int32(200), res.Status)

	var event map[string]interface{}
	require.NoError(t, json.Unmarshal(res.Payload, &event))
	assert.Equal(t, "RANSOMWARE", event["attack_category"])
}

func TestGetNonExistentEvent(t *testing.T) {
	stub := shimtest.NewMockStub("security_logger", new(SecurityLoggerChaincode))
	res := stub.MockInvoke("tx4", [][]byte{[]byte("GetSecurityEvent"), []byte("nonexistent")})
	assert.Equal(t, int32(404), res.Status)
}
