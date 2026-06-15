"""Storage cost analysis: on-chain vs IPFS hybrid model."""
import json
import sys


AVG_RAW_PAYLOAD_BYTES = 2048      # average full event JSON
AVG_ONCHAIN_BYTES = 512           # event metadata stored on-chain
IPFS_CID_BYTES = 59               # CIDv1 string length
SHA256_BYTES = 64                 # hex SHA-256
FABRIC_OVERHEAD_PER_TX = 256      # Fabric tx envelope overhead


def analyse(num_events: int) -> dict:
    # On-chain storage (metadata + CID + hash)
    per_event_onchain = AVG_ONCHAIN_BYTES + IPFS_CID_BYTES + SHA256_BYTES + FABRIC_OVERHEAD_PER_TX
    total_onchain_bytes = num_events * per_event_onchain

    # IPFS storage (full payloads)
    total_ipfs_bytes = num_events * AVG_RAW_PAYLOAD_BYTES

    # Naive on-chain only (for comparison)
    total_naive_bytes = num_events * (AVG_RAW_PAYLOAD_BYTES + FABRIC_OVERHEAD_PER_TX)

    savings_bytes = total_naive_bytes - total_onchain_bytes
    savings_pct = (savings_bytes / total_naive_bytes) * 100 if total_naive_bytes else 0

    return {
        "num_events": num_events,
        "on_chain_total_mb": round(total_onchain_bytes / 1024 / 1024, 2),
        "ipfs_total_mb": round(total_ipfs_bytes / 1024 / 1024, 2),
        "hybrid_total_mb": round((total_onchain_bytes + total_ipfs_bytes) / 1024 / 1024, 2),
        "naive_onchain_total_mb": round(total_naive_bytes / 1024 / 1024, 2),
        "savings_mb": round(savings_bytes / 1024 / 1024, 2),
        "savings_pct": round(savings_pct, 1),
        "per_event_onchain_bytes": per_event_onchain,
        "per_event_ipfs_bytes": AVG_RAW_PAYLOAD_BYTES,
    }


if __name__ == "__main__":
    for n in [1_000, 10_000, 100_000, 1_000_000]:
        result = analyse(n)
        print(json.dumps(result, indent=2))
        print()
