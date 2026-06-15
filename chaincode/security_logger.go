package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type SecurityEvent struct {
	EventID            string `json:"event_id"`
	PayloadHash        string `json:"payload_hash"`        // SHA-256 hash of full event payload
	IPFSCID            string `json:"ipfs_cid"`            // IPFS content identifier for off-chain payload
	Timestamp          string `json:"timestamp"`
	Severity           string `json:"severity"`            // LOW, MEDIUM, HIGH, CRITICAL
	AttackCategory     string `json:"attack_category"`     // DDoS, InsiderThreat, PrivEsc, PortScan, Normal
	DetectionConfidence float64 `json:"detection_confidence"` // 0.0-1.0
	ModelVersion       string `json:"model_version"`
	AgentIdentity      string `json:"agent_identity"`      // X.509 CN from Fabric CA
	AgentSignature     string `json:"agent_signature"`     // ECDSA signature (hex)
	CloudAssetID       string `json:"cloud_asset_id"`      // affected cloud resource ID
}

// LogSecurityEvent writes a cryptographic hash of the event payload and metadata to the ledger.
// Only authenticated detection agents can call this function (enforced via Fabric MSP).
func (s *SmartContract) LogSecurityEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	payloadHash string,
	ipfsCID string,
	timestamp string,
	severity string,
	attackCategory string,
	detectionConfidence float64,
	modelVersion string,
	agentIdentity string,
	agentSignature string,
	cloudAssetID string,
) error {
	// Access control: only org1 detection agents may write
	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %v", err)
	}
	if clientMSP != "Org1MSP" {
		return fmt.Errorf("unauthorized: only Org1MSP detection agents may log events, got %s", clientMSP)
	}

	exists, err := s.EventExists(ctx, eventID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the security event %s already exists", eventID)
	}

	// Use ledger timestamp if none provided
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	event := SecurityEvent{
		EventID:             eventID,
		PayloadHash:         payloadHash,
		IPFSCID:             ipfsCID,
		Timestamp:           timestamp,
		Severity:            severity,
		AttackCategory:      attackCategory,
		DetectionConfidence: detectionConfidence,
		ModelVersion:        modelVersion,
		AgentIdentity:       agentIdentity,
		AgentSignature:      agentSignature,
		CloudAssetID:        cloudAssetID,
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Emit chaincode event for off-chain listeners
	ctx.GetStub().SetEvent("SecurityEventLogged", eventJSON)

	return ctx.GetStub().PutState(eventID, eventJSON)
}

// VerifyEvent queries the ledger to confirm the integrity of a specified event record against its stored hash.
// Returns the full event metadata; callers should re-hash the IPFS payload and compare with PayloadHash.
func (s *SmartContract) VerifyEvent(ctx contractapi.TransactionContextInterface, eventID string) (*SecurityEvent, error) {
	eventJSON, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if eventJSON == nil {
		return nil, fmt.Errorf("the security event %s does not exist", eventID)
	}

	var event SecurityEvent
	if err = json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}

	return &event, nil
}

// QueryEventHistory retrieves the complete, ordered audit trail for a given cloud asset.
// Supports time-window filtering (ISO 8601 timestamps). Pass empty strings to skip filtering.
func (s *SmartContract) QueryEventHistory(
	ctx contractapi.TransactionContextInterface,
	cloudAssetID string,
	fromTimestamp string,
	toTimestamp string,
) ([]*SecurityEvent, error) {
	// Rich query using CouchDB index (requires CouchDB state DB)
	queryString := fmt.Sprintf(`{"selector":{"cloud_asset_id":"%s"`, cloudAssetID)

	if fromTimestamp != "" && toTimestamp != "" {
		queryString += fmt.Sprintf(`,"timestamp":{"$gte":"%s","$lte":"%s"}`, fromTimestamp, toTimestamp)
	} else if fromTimestamp != "" {
		queryString += fmt.Sprintf(`,"timestamp":{"$gte":"%s"}`, fromTimestamp)
	} else if toTimestamp != "" {
		queryString += fmt.Sprintf(`,"timestamp":{"$lte":"%s"}`, toTimestamp)
	}

	queryString += `},"sort":[{"timestamp":"asc"}]}`

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to execute rich query: %v", err)
	}
	defer resultsIterator.Close()

	var events []*SecurityEvent
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var event SecurityEvent
		if err = json.Unmarshal(queryResponse.Value, &event); err != nil {
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// QueryEventsBySeverity retrieves all events for a given severity level (compliance reporting).
func (s *SmartContract) QueryEventsBySeverity(ctx contractapi.TransactionContextInterface, severity string) ([]*SecurityEvent, error) {
	queryString := fmt.Sprintf(`{"selector":{"severity":"%s"},"sort":[{"timestamp":"desc"}]}`, severity)

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to query by severity: %v", err)
	}
	defer resultsIterator.Close()

	var events []*SecurityEvent
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var event SecurityEvent
		if err = json.Unmarshal(queryResponse.Value, &event); err != nil {
			return nil, err
		}
		events = append(events, &event)
	}

	return events, nil
}

// EventExists returns true when asset with given ID exists in world state.
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
		fmt.Printf("Error creating security logging chaincode: %s\n", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting security logging chaincode: %s\n", err.Error())
	}
}
