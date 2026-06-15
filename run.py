#!/usr/bin/env python3
"""
run.py  —  Live executor for Objective 2
           Blockchain-Based Immutable Audit Trail for AI-Driven Cloud Security

Usage:
    python run.py                  # full live run (requires Docker + Fabric + IPFS + Kafka)
    python run.py --teardown       # stop and remove all containers/volumes
    python run.py --results-only   # re-print last saved results
    python run.py --skip-docker    # skip Docker/channel steps, just start services
    python run.py --mock           # NOT SUPPORTED — exits with error

NOTE: There is no mock/simulation mode in this runner.
      For unit tests, set MOCK_MODE=1 and run pytest tests/.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import statistics
import socket
from datetime import datetime, timezone
from pathlib import Path

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
SEP = "-" * 60

def ok(msg):   print(f"{GREEN}  \u2714  {msg}{RESET}")
def warn(msg): print(f"{YELLOW}  \u26a0  {msg}{RESET}")
def err(msg):  print(f"{RED}  \u2718  {msg}{RESET}")
def info(msg): print(f"{CYAN}  \u25b6  {msg}{RESET}")
def hdr(msg):  print(f"\n{BOLD}{CYAN}{SEP}\n  {msg}\n{SEP}{RESET}")

def die(msg):
    err(msg)
    sys.exit(1)

RESULTS_FILE = Path("results/run_results.json")
RESULTS_FILE.parent.mkdir(exist_ok=True)

VENV_DIR = Path(__file__).parent.resolve() / ".venv"

FABRIC_HOSTS = [
    "peer0.org1.example.com",
    "peer1.org1.example.com",
    "orderer.example.com",
    "ca.org1.example.com",
]


# ============================================================
# venv helpers
# ============================================================

def _venv_python_path() -> Path:
    for name in ("python3", "python"):
        c = VENV_DIR / "bin" / name
        if c.exists():
            return c
    win = VENV_DIR / "Scripts" / "python.exe"
    if win.exists():
        return win
    return VENV_DIR / "bin" / "python3"


def _venv_pip_path() -> Path:
    for name in ("pip3", "pip"):
        c = VENV_DIR / "bin" / name
        if c.exists():
            return c
    win = VENV_DIR / "Scripts" / "pip.exe"
    if win.exists():
        return win
    return VENV_DIR / "bin" / "pip3"


def _make_venv():
    if VENV_DIR.exists():
        shutil.rmtree(str(VENV_DIR))
    info(f"Creating venv at {VENV_DIR} ...")
    subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
    ok(".venv created")


def ensure_venv():
    if not _venv_python_path().exists():
        _make_venv()
    venv_python = _venv_python_path()
    venv_pip    = _venv_pip_path()
    if not venv_python.exists():
        raise RuntimeError(f"venv python not found at {venv_python}")
    subprocess.call([str(venv_pip), "install", "--upgrade", "pip", "-q"])
    for req in sorted(Path("services").rglob("requirements.txt")):
        info(f"Installing {req} ...")
        rc = subprocess.call([str(venv_pip), "install", "-r", str(req), "-q"])
        if rc == 0:
            ok(f"  {req} — done")
        else:
            warn(f"  {req} — some packages failed")
    ok(f"Using venv python: {venv_python}")
    return str(venv_python), str(venv_pip)


# ============================================================
# /etc/hosts injection
# ============================================================

def _hosts_already_patched() -> bool:
    try:
        return "peer0.org1.example.com" in Path("/etc/hosts").read_text()
    except Exception:
        return True


def inject_etc_hosts():
    if platform.system() != "Linux":
        return
    if _hosts_already_patched():
        ok("Fabric hostnames already in /etc/hosts")
        return
    entries = "\n# Hyperledger Fabric local dev (added by run.py)\n"
    for h in FABRIC_HOSTS:
        entries += f"127.0.0.1  {h}\n"
    try:
        result = subprocess.run(["sudo", "tee", "-a", "/etc/hosts"],
                                input=entries, capture_output=True, text=True)
        if result.returncode == 0:
            ok("Fabric hostnames injected into /etc/hosts")
            return
    except FileNotFoundError:
        pass
    try:
        with open("/etc/hosts", "a") as fh:
            fh.write(entries)
        ok("Fabric hostnames injected (direct write)")
        return
    except PermissionError:
        pass
    warn("Could not inject /etc/hosts — run manually:")
    warn("  sudo bash -c 'echo \"127.0.0.1  peer0.org1.example.com orderer.example.com\" >> /etc/hosts'")


# ============================================================
# FABRIC_CFG_PATH
# ============================================================

def find_fabric_cfg_path() -> str:
    candidates = [
        Path(__file__).parent / "fabric-samples" / "config",
        Path.home() / "fabric-samples" / "config",
        Path(os.environ.get("FABRIC_CFG_PATH", "")),
    ]
    for c in candidates:
        if c and (c / "core.yaml").exists():
            return str(c)
    cfg_dir   = Path(__file__).parent / "fabric-config"
    cfg_dir.mkdir(exist_ok=True)
    core_yaml = cfg_dir / "core.yaml"
    if not core_yaml.exists():
        info("Writing minimal core.yaml into ./fabric-config/ ...")
        core_yaml.write_text("peer:\n  id: peer0.org1.example.com\n")
    return str(cfg_dir)


# ============================================================
# Orderer TLS CA probe
# ============================================================

def _find_orderer_tls_ca() -> str:
    base = Path("crypto-config/ordererOrganizations/example.com")
    candidates = [
        base / "orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem",
        base / "tlsca/tlsca.example.com-cert.pem",
        base / "orderers/orderer.example.com/tls/ca.crt",
    ]
    for c in candidates:
        if c.exists():
            return str(c.resolve())
    warn("Orderer TLS CA cert not found — tried:")
    for c in candidates:
        warn(f"  {c}")
    return str(candidates[0].resolve())


# ============================================================
# Idempotent lifecycle checks  (EXPLICIT — fail fast if broken)
# ============================================================

def _peer_env(fabric_cfg: str) -> dict:
    peer_tls_ca = str(
        Path("crypto-config/peerOrganizations/org1.example.com"
             "/peers/peer0.org1.example.com/tls/ca.crt").resolve()
    )
    return {
        **os.environ,
        "FABRIC_CFG_PATH":         fabric_cfg,
        "CORE_PEER_TLS_ENABLED":   "true",
        "CORE_PEER_LOCALMSPID":    "Org1MSP",
        "CORE_PEER_ADDRESS":       "peer0.org1.example.com:7051",
        "CORE_PEER_MSPCONFIGPATH": str(
            Path("crypto-config/peerOrganizations/org1.example.com"
                 "/users/Admin@org1.example.com/msp").resolve()
        ),
        "CORE_PEER_TLS_ROOTCERT_FILE": peer_tls_ca,
    }


def _check_channel_exists(channel: str, env: dict) -> bool:
    r = subprocess.run(
        ["peer", "channel", "list"], env=env, capture_output=True, text=True
    )
    return channel in r.stdout


def _check_peer_joined(channel: str, env: dict) -> bool:
    r = subprocess.run(
        ["peer", "channel", "list"], env=env, capture_output=True, text=True
    )
    return channel in r.stdout


def _check_pkg_installed(label: str, env: dict) -> str:
    """Return package ID if installed, empty string otherwise."""
    r = subprocess.run(
        ["peer", "lifecycle", "chaincode", "queryinstalled"],
        env=env, capture_output=True, text=True,
    )
    for line in r.stdout.splitlines():
        if label in line and "Package ID:" in line:
            return line.split("Package ID:")[1].split(",")[0].strip()
    return ""


def _check_approved(channel: str, name: str, sequence: str, env: dict) -> bool:
    r = subprocess.run(
        ["peer", "lifecycle", "chaincode", "checkcommitreadiness",
         "--channelID", channel, "--name", name,
         "--version", "1.0", "--sequence", sequence, "--output", "json"],
        env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False
    try:
        return json.loads(r.stdout).get("approvals", {}).get("Org1MSP", False) is True
    except Exception:
        return "Org1MSP: true" in r.stdout


def _check_committed(channel: str, name: str, env: dict) -> bool:
    r = subprocess.run(
        ["peer", "lifecycle", "chaincode", "querycommitted",
         "--channelID", channel, "--name", name],
        env=env, capture_output=True, text=True,
    )
    return r.returncode == 0 and name in r.stdout


# ============================================================
# 1. PREREQUISITE CHECKS  (live only — dies if anything missing)
# ============================================================

def check_prereqs() -> bool:
    hdr("Step 1 — Prerequisite Check (live)")
    all_ok = True

    def chk(name, cmd):
        nonlocal all_ok
        if shutil.which(cmd[0]) is None:
            err(f"{name} not found — install it first")
            all_ok = False
            return
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True).strip()
            ok(f"{name}: {out.splitlines()[0]}")
        except Exception as e:
            warn(f"{name}: found but version check failed ({e})")

    chk("Python",        ["python3", "--version"])
    chk("Docker",        ["docker", "--version"])
    chk("Docker Compose",["docker", "compose", "version"])
    chk("Go",            ["go", "version"])

    for bin_ in ["cryptogen", "configtxgen", "peer"]:
        if shutil.which(bin_):
            ok(f"Fabric binary: {bin_