"""IPFS client — delegates to shared/ipfs.py (real Kubo HTTP API)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.ipfs import add_and_pin, fetch_and_verify  # noqa: F401 — re-export
