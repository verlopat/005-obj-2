#!/bin/bash

echo "--- Step 1: Initializing Go Module for Chaincode ---"
cd chaincode
go mod init security_logger
go get github.com/hyperledger/fabric-contract-api-go/contractapi
go mod vendor
cd ..

echo "--- Step 2: Starting the Fabric Test Network ---"
cd fabric-samples/test-network

# Shut down any running networks and clean up old containers/volumes
./network.sh down

# Bring up the network with Certificate Authorities and create a channel
./network.sh up createChannel -c mychannel -ca

echo "--- Step 3: Deploying the Security Logger Chaincode ---"
# Note: The chaincode path is relative to the test-network directory.
# Since test-network is inside fabric-samples, we go up two levels to reach the root chaincode directory.
./network.sh deployCC -ccn security_logger -ccp ../../chaincode -ccl go

echo "--- Network and Chaincode Deployment Complete! ---"
