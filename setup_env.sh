#!/usr/bin/env bash
# =============================================================================
#  setup_env.sh  —  Bootstrap the Python virtual environment for Objective 2
#
#  Usage:
#    chmod +x setup_env.sh
#    ./setup_env.sh
#    source .env/bin/activate
#
#  After activation:
#    python run.py          # full live run (Docker + Fabric required)
#    python run.py --teardown
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}  ✔  ${1}${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠  ${1}${RESET}"; }
err()  { echo -e "${RED}  ✘  ${1}${RESET}"; }
info() { echo -e "${CYAN}  ▶  ${1}${RESET}"; }
hdr()  { echo -e "\n${BOLD}${CYAN}------------------------------------------------------------\n  ${1}\n------------------------------------------------------------${RESET}"; }

VENV_DIR=".env"
PYTHON=""

# ── Locate a suitable Python 3.9+ interpreter ────────────────────────────────
hdr "Step 1 — Locate Python 3.9+"
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
            PYTHON="$candidate"
            ok "Found: $($PYTHON --version)  →  $PYTHON"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    err "Python 3.9+ not found. Install it first."
    exit 1
fi

# ── (Re)create the venv ───────────────────────────────────────────────────────
hdr "Step 2 — Create virtual environment at ./${VENV_DIR}/"

if [ -d "${VENV_DIR}" ]; then
    if [ -f "${VENV_DIR}/bin/python3" ] || [ -f "${VENV_DIR}/Scripts/python.exe" ]; then
        ok "Existing venv looks healthy — skipping recreation"
        ok "  (delete .env/ and re-run to force a clean rebuild)"
    else
        warn ".env/ exists but has no python binary — nuking and recreating"
        rm -rf "${VENV_DIR}"
        "$PYTHON" -m venv "${VENV_DIR}"
        ok "Venv created at ./${VENV_DIR}/"
    fi
else
    info "Creating venv ..."
    "$PYTHON" -m venv "${VENV_DIR}"
    ok "Venv created at ./${VENV_DIR}/"
fi

# ── Resolve venv python/pip ───────────────────────────────────────────────────
if [ -f "${VENV_DIR}/bin/python3" ]; then
    VENV_PYTHON="${VENV_DIR}/bin/python3"
    VENV_PIP="${VENV_DIR}/bin/pip3"
elif [ -f "${VENV_DIR}/bin/python" ]; then
    VENV_PYTHON="${VENV_DIR}/bin/python"
    VENV_PIP="${VENV_DIR}/bin/pip"
elif [ -f "${VENV_DIR}/Scripts/python.exe" ]; then
    VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
    VENV_PIP="${VENV_DIR}/Scripts/pip.exe"
else
    err "Cannot find python inside ${VENV_DIR}/ — venv creation failed."
    exit 1
fi

ok "Venv python : $($VENV_PYTHON --version)"
ok "Venv pip    : $($VENV_PIP --version | head -c 40)"

# ── Upgrade pip & install build tools ────────────────────────────────────────
hdr "Step 3 — Upgrade pip + install wheel/setuptools"
"$VENV_PIP" install --upgrade pip wheel setuptools -q
ok "pip/wheel/setuptools upgraded"

# ── Install root-level requirements (if present) ─────────────────────────────
if [ -f "requirements.txt" ]; then
    hdr "Step 4 — Install root requirements.txt"
    "$VENV_PIP" install -r requirements.txt -q
    ok "Root requirements installed"
fi

# ── Install every service requirements.txt ───────────────────────────────────
hdr "Step 5 — Install service requirements"
SERVICES=("services/detector-adapter" "services/blockchain-logger" "services/audit-api" "services/compliance-scheduler")
for svc in "${SERVICES[@]}"; do
    req="${svc}/requirements.txt"
    if [ -f "$req" ]; then
        info "  Installing ${req} ..."
        "$VENV_PIP" install -r "$req" -q
        ok "  ${svc} — done"
    else
        warn "  ${req} not found — skipping"
    fi
done

# ── Install top-level script dependencies ────────────────────────────────────
hdr "Step 6 — Install top-level script deps"
"$VENV_PIP" install requests cryptography flask "confluent-kafka>=2.3" apscheduler python-dotenv -q
ok "Script deps installed (includes python-dotenv for .env loading)"

# ── Copy .env.example → .env if not already present ─────────────────────────
hdr "Step 7 — Environment config"
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        ok "Copied .env.example → .env  (edit paths as needed)"
    else
        warn ".env.example not found — skipping .env creation"
    fi
else
    ok ".env already exists — not overwriting"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}============================================================"
echo -e "  ✔  Environment ready!"
echo -e "============================================================${RESET}"
echo ""
echo -e "  ${CYAN}Activate with:${RESET}"
echo -e "    ${BOLD}source .env/bin/activate${RESET}"
echo ""
echo -e "  ${CYAN}Then run:${RESET}"
echo -e "    ${BOLD}python run.py${RESET}               # full live run"
echo -e "    ${BOLD}python run.py --teardown${RESET}    # stop Docker stack"
echo ""
echo -e "  ${CYAN}Deactivate when done:${RESET}"
echo -e "    ${BOLD}deactivate${RESET}"
echo ""
