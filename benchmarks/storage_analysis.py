"""Estimate Hyperledger Fabric blockchain storage growth for security events."""
import json
from dataclasses import dataclass, asdict
from typing import List

@dataclass
class StorageEstimate:
    events_per_day: int
    avg_event_size_bytes: int
    avg_ipfs_payload_bytes: int
    days: int
    replication_factor: int = 3
    couchdb_overhead_multiplier: float = 3.0
    leveldb_overhead_multiplier: float = 1.5

    @property
    def total_events(self) -> int:
        return self.events_per_day * self.days

    @property
    def raw_ledger_bytes(self) -> int:
        return self.total_events * self.avg_event_size_bytes

    @property
    def replicated_ledger_bytes(self) -> int:
        return self.raw_ledger_bytes * self.replication_factor

    @property
    def couchdb_state_db_bytes(self) -> int:
        return int(self.raw_ledger_bytes * self.couchdb_overhead_multiplier)

    @property
    def ipfs_storage_bytes(self) -> int:
        return self.total_events * self.avg_ipfs_payload_bytes

    @property
    def total_storage_bytes(self) -> int:
        return self.replicated_ledger_bytes + self.couchdb_state_db_bytes + self.ipfs_storage_bytes

    def summary(self) -> dict:
        def fmt_gb(b): return round(b / 1e9, 3)
        return {
            "scenario": f"{self.events_per_day:,} events/day x {self.days} days",
            "total_events": f"{self.total_events:,}",
            "ledger_per_peer_gb": fmt_gb(self.raw_ledger_bytes),
            "ledger_replicated_gb": fmt_gb(self.replicated_ledger_bytes),
            "couchdb_state_db_gb": fmt_gb(self.couchdb_state_db_bytes),
            "ipfs_storage_gb": fmt_gb(self.ipfs_storage_bytes),
            "total_storage_gb": fmt_gb(self.total_storage_bytes),
        }

if __name__ == "__main__":
    scenarios = [
        StorageEstimate(events_per_day=10_000,  avg_event_size_bytes=2048, avg_ipfs_payload_bytes=4096, days=30),
        StorageEstimate(events_per_day=100_000, avg_event_size_bytes=2048, avg_ipfs_payload_bytes=4096, days=30),
        StorageEstimate(events_per_day=1_000_000, avg_event_size_bytes=2048, avg_ipfs_payload_bytes=4096, days=30),
        StorageEstimate(events_per_day=100_000, avg_event_size_bytes=2048, avg_ipfs_payload_bytes=4096, days=365),
    ]
    print(json.dumps([s.summary() for s in scenarios], indent=2))
