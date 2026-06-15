package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type SecurityEvent struct {
	EventID       string `json:"event_id"`
	PayloadHash   string `json:"payload_hash"`   // IPFS CID or SHA-256 hash
	Timestamp     string `json:"timestamp"`
	Severity      string `json:"severity"`
	AgentIdentity string `json:"agent_identity"` // PKI signature or identity
}

// LogSecurityEvent writes a cryptographic hash of the event payload and metadata to the ledger
func (s *SmartContract) LogSecurityEvent(ctx contractapi.TransactionContextInterface, eventID string, payloadHash string, timestamp string, severity string, agentIdentity string) error {
	exists, err := s.EventExists(ctx, eventID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the security event %s already exists", eventID)
	}

	event := SecurityEvent{
		EventID:       eventID,
		PayloadHash:   payloadHash,
		Timestamp:     timestamp,
		Severity:      severity,
		AgentIdentity: agentIdentity,
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(eventID, eventJSON)
}

// VerifyEvent queries the ledger to confirm the integrity of a specified event record
func (s *SmartContract) VerifyEvent(ctx contractapi.TransactionContextInterface, eventID string) (*SecurityEvent, error) {
	eventJSON, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if eventJSON == nil {
		return nil, fmt.Errorf("the security event %s does not exist", eventID)
	}

	var event SecurityEvent
	err = json.Unmarshal(eventJSON, &event)
	if err != nil {
		return nil, err
	}

	return &event, nil
}

// EventExists returns true when asset with given ID exists in world state
func (s *SmartContract) EventExists(ctx contractapi.TransactionContextInterface, eventID string) (bool, error) {
	eventJSON, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return eventJSON != nil, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating security logging chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting security logging chaincode: %s", err.Error())
	}
}
