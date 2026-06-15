# Threat Model

## Scope

This document covers the threat model for the blockchain-based security event logging pipeline.

## Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Security event records | High | On-chain immutable audit trail |
| IPFS payloads | High | Full event details including raw payload |
| Signing private keys | Critical | ECDSA P-256 keys for non-repudiation |
| Fabric MSP certificates | High | Org1MSP identity credentials |
| Kafka event stream | Medium | In-transit security events |

## Threat Actors

- **External attacker**: Unauthenticated network adversary attempting to inject false events or tamper with records.
- **Compromised detection agent**: An AI agent with valid credentials that submits falsified severity or category data.
- **Malicious insider**: Org1MSP member attempting to delete or modify logged events.
- **Infrastructure attacker**: Adversary with access to Kafka or IPFS infrastructure attempting to tamper with events in transit.

## Mitigations

| Threat | STRIDE | Mitigation |
|---|---|---|
| Inject false events | Spoofing | Org1MSP certificate-based auth; ECDSA signatures |
| Tamper with logged events | Tampering | Fabric append-only ledger; SHA-256 integrity check |
| Replay events | Repudiation | Event UUID deduplication in chaincode |
| Exfiltrate event data | Information Disclosure | TLS on all channels; IPFS access controls |
| Overwhelm ingestion API | Denial of Service | HPA autoscaling; Kafka backpressure; rate limiting |
| Escalate privileges | Elevation of Privilege | MSP-based ABAC; chaincode access control |
| Tamper IPFS payload | Tampering | SHA-256 hash stored immutably on-chain; integrity spot checks |
