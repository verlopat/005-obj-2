"""Estimate on-chain vs off-chain storage usage and per-event byte cost."""
import json
import sys

# Approximate sizes (bytes)
ON_CHAIN_FIELDS = {
    "event_id":             36,
    "asset_id":             64,
    "severity":             8,
    "attack_category":      20,
    "description_truncated":128,
    "ipfs_cid":             59,   # CIDv1 base32 ~ 59 chars
    "sha256":               64,
    "tx_id":                64,
    "detection_confidence":  8,
    "model_version":        8,
    "signature_b64":        96,   # ECDSA P-256 DER ~72 bytes, base64 ~96
    "timestamp":            24,
    "metadata_overhead":    200,  # Fabric key, namespace, version, metadata
}

OFF_CHAIN_RAW_PAYLOAD = 4096   # max raw payload size stored in IPFS
IPFS_BLOCK_OVERHEAD   = 256


def compute_costs(num_events: int = 1_000_000) -> None:
    on_chain_bytes  = sum(ON_CHAIN_FIELDS.values())
    off_chain_bytes = OFF_CHAIN_RAW_PAYLOAD + IPFS_BLOCK_OVERHEAD
    total_on_chain  = on_chain_bytes  * num_events
    total_off_chain = off_chain_bytes * num_events

    results = {
        "per_event": {
            "on_chain_bytes":  on_chain_bytes,
            "off_chain_bytes": off_chain_bytes,
            "total_bytes":     on_chain_bytes + off_chain_bytes,
        },
        f"{num_events:,}_events": {
            "on_chain_MB":  round(total_on_chain  / 1e6, 2),
            "off_chain_MB": round(total_off_chain / 1e6, 2),
            "total_MB":     round((total_on_chain + total_off_chain) / 1e6, 2),
            "on_chain_GB":  round(total_on_chain  / 1e9, 4),
            "off_chain_GB": round(total_off_chain / 1e9, 4),
        },
        "on_chain_field_breakdown": ON_CHAIN_FIELDS,
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    compute_costs(n)
