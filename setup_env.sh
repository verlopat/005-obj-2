#!/usr/bin/env bash
# =============================================================================
#  setup_env.sh  —  Install deps into system/user Python for Objective 2
#
#  No virtual environment is created.
#  Deps are installed into the active Python environment (system or conda).
#
#  Usage (one-time):
#    chmod +x setup_env.sh
#    ./setup_env.sh
#
#  Every session after that:
#    source activate_project.sh   # just exports project.env vars
#    python run.py
# =============================================================================

set -euo pipefail

GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}  ✔  ${1}${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠  ${1}${RESET}"; }
err()  { echo -e "${RED}  ✘  ${1}${RESET}"; }
info() { echo -e "${CYAN}  ▶  ${1}${RESET}"; }
hdr()  { echo -e "\n${BOLD}${CYAN}------------------------------------------------------------\n  ${1}\n------------------------------------------------------------${RESET}"; }

# ── Step 1: Locate Python 3.9+ ───────────────────────────────────────────────
hdr "Step 1 — Locate Python 3.9+"
PYTHON=""
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

PIP="$PYTHON -m pip"

# ── Step 2: Upgrade pip ───────────────────────────────────────────────────────
hdr "Step 2 — Upgrade pip"
$PYTHON -m pip install --upgrade pip -q
ok "pip upgraded"

# ── Step 3: Install service requirements ─────────────────────────────────────
hdr "Step 3 — Install service requirements"
SERVICES=("services/detector-adapter" "services/blockchain-logger" "services/audit-api" "services/compliance-scheduler")
for svc in "${SERVICES[@]}"; do
    req="${svc}/requirements.txt"
    if [ -f "$req" ]; then
        info "  Installing ${req} ..."
        $PYTHON -m pip install -r "$req" -q
        ok "  ${svc} — done"
    else
        warn "  ${req} not found — skipping"
    fi
done

# ── Step 4: Top-level script deps ────────────────────────────────────────────
hdr "Step 4 — Install top-level script deps"
$PYTHON -m pip install requests cryptography flask "confluent-kafka>=2.3" apscheduler python-dotenv redis -q
ok "Script deps installed"

# ── Step 5: Copy project.env.example → project.env ───────────────────────────
hdr "Step 5 — Environment config"
if [ ! -f "project.env" ]; then
    if [ -f "project.env.example" ]; then
        cp project.env.example project.env
        ok "Copied project.env.example → project.env"
        warn "Edit project.env and set correct values before running python run.py"
    else
        warn "project.env.example not found — skipping"
    fi
else
    ok "project.env already exists — not overwriting"
fi

# ── Step 6: Write activate_project.sh ────────────────────────────────────────
hdr "Step 6 — Write activate_project.sh helper"
cat > activate_project.sh << 'EOF'
#!/usr/bin/env bash
# Exports project.env vars into the current shell.
# Usage:  source activate_project.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
echo -e "  ✔  Setup complete!"
echo -e "============================================================${RESET}"
echo ""
echo -e "  ${CYAN}Every session — just run:${RESET}"
echo -e "    ${BOLD}source activate_project.sh${RESET}   # export env vars"
echo -e "    ${BOLD}python run.py${RESET}                 # full live run"
echo -e "    ${BOLD}python run.py --teardown${RESET}      # stop Docker stack"
echo ""
echo -e "  ${YELLOW}Edit project.env before first run.${RESET}"
echo ""
