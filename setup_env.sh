#!/usr/bin/env bash
# =============================================================================
#  setup_env.sh  —  Bootstrap the Python virtual environment for Objective 2
#
#  Usage (one-time setup):
#    chmod +x setup_env.sh
#    ./setup_env.sh
#
#  Every session after that:
#    source activate_project.sh
#    python run.py
# =============================================================================

set -euo pipefail

GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}  ✔  ${1}${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠  ${1}${RESET}"; }
err()  { echo -e "${RED}  ✘  ${1}${RESET}"; }
info() { echo -e "${CYAN}  ▶  ${1}${RESET}"; }
hdr()  { echo -e "\n${BOLD}${CYAN}------------------------------------------------------------\n  ${1}\n------------------------------------------------------------${RESET}"; }

VENV_DIR=".env"
PYTHON=""

# ── Step 1: Locate Python 3.9+ ───────────────────────────────────────────────
hdr "Step 1 — Locate Python 3.9+"
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9; do
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

# ── Step 2: (Re)create the venv at .env/ ─────────────────────────────────────
hdr "Step 2 — Create virtual environment at ./${VENV_DIR}/"

if [ -d "${VENV_DIR}" ]; then
    if [ -f "${VENV_DIR}/bin/python3" ] || [ -f "${VENV_DIR}/Scripts/python.exe" ]; then
        ok "Existing venv healthy — skipping recreation"
    else
        warn ".env/ exists but no python binary found — recreating"
        rm -rf "${VENV_DIR}"
        "$PYTHON" -m venv "${VENV_DIR}"
        ok "Venv created at ./${VENV_DIR}/"
    fi
else
    info "Creating venv ..."
    "$PYTHON" -m venv "${VENV_DIR}"
    ok "Venv created at ./${VENV_DIR}/"
fi

if   [ -f "${VENV_DIR}/bin/python3" ];        then VENV_PYTHON="${VENV_DIR}/bin/python3";       VENV_PIP="${VENV_DIR}/bin/pip3"
elif [ -f "${VENV_DIR}/bin/python" ];         then VENV_PYTHON="${VENV_DIR}/bin/python";        VENV_PIP="${VENV_DIR}/bin/pip"
elif [ -f "${VENV_DIR}/Scripts/python.exe" ]; then VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"; VENV_PIP="${VENV_DIR}/Scripts/pip.exe"
else err "Cannot find python inside ${VENV_DIR}/ — venv creation failed."; exit 1
fi

ok "Venv python : $($VENV_PYTHON --version)"
ok "Venv pip    : $($VENV_PIP --version | head -c 50)"

# ── Step 3: Upgrade pip + build tools ────────────────────────────────────────
hdr "Step 3 — Upgrade pip + wheel/setuptools"
"$VENV_PIP" install --upgrade pip wheel setuptools -q
ok "pip/wheel/setuptools upgraded"

# ── Step 4: Root requirements.txt (if exists) ────────────────────────────────
if [ -f "requirements.txt" ]; then
    hdr "Step 4 — Install root requirements.txt"
    "$VENV_PIP" install -r requirements.txt -q
    ok "Root requirements installed"
fi

# ── Step 5: All service requirements.txt ─────────────────────────────────────
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

# ── Step 6: Top-level script deps ────────────────────────────────────────────
hdr "Step 6 — Install top-level script deps"
"$VENV_PIP" install requests cryptography flask "confluent-kafka>=2.3" apscheduler python-dotenv redis -q
ok "Script deps installed"

# ── Step 7: Copy project.env.example → project.env ───────────────────────────
# NOTE: env vars file is "project.env" NOT ".env" because ".env" is the venv dir.
hdr "Step 7 — Environment config (project.env)"
if [ ! -f "project.env" ]; then
    if [ -f "project.env.example" ]; then
        cp project.env.example project.env
        ok "Copied project.env.example → project.env"
        warn "Edit project.env and set correct paths before running python run.py"
    else
        warn "project.env.example not found — skipping"
    fi
else
    ok "project.env already exists — not overwriting"
fi

# ── Step 8: Write activate_project.sh convenience wrapper ────────────────────
hdr "Step 8 — Write activate_project.sh helper"
cat > activate_project.sh << 'EOF'
#!/usr/bin/env bash
# Activates the venv AND exports project.env vars in one shot.
# Usage:  source activate_project.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Activate Python venv (.env/)
if [ -f "${SCRIPT_DIR}/.env/bin/activate" ]; then
    source "${SCRIPT_DIR}/.env/bin/activate"
    echo -e "\033[92m  ✔  venv activated (.env/)\033[0m"
else
    echo -e "\033[91m  ✘  .env/bin/activate not found — run ./setup_env.sh first\033[0m"
    return 1
fi

# 2. Export all vars from project.env into shell
if [ -f "${SCRIPT_DIR}/project.env" ]; then
    set -a
    source "${SCRIPT_DIR}/project.env"
    set +a
    echo -e "\033[92m  ✔  project.env vars exported\033[0m"
else
    echo -e "\033[93m  ⚠  project.env not found — run ./setup_env.sh first\033[0m"
fi

echo ""
echo -e "\033[96m  Ready. Run:\033[0m  python run.py"
echo ""
EOF
chmod +x activate_project.sh
ok "activate_project.sh written"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}============================================================"
echo -e "  ✔  Environment ready!"
echo -e "============================================================${RESET}"
echo ""
echo -e "  ${CYAN}Every session — just run ONE command:${RESET}"
echo -e "    ${BOLD}source activate_project.sh${RESET}"
echo ""
echo -e "  ${CYAN}Then:${RESET}"
echo -e "    ${BOLD}python run.py${RESET}               # full live run"
echo -e "    ${BOLD}python run.py --teardown${RESET}    # stop Docker stack"
echo ""
echo -e "  ${YELLOW}NOTE: env vars file is 'project.env' (not '.env')${RESET}"
echo -e "  ${YELLOW}      Edit project.env before first run.${RESET}"
echo ""
echo -e "  ${CYAN}Deactivate:${RESET}  ${BOLD}deactivate${RESET}"
echo ""
