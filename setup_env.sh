#!/usr/bin/env bash
# setup_env.sh  —  One-time environment bootstrap for Objective 2
# Run once after cloning.  Safe to re-run (idempotent).

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo ""
echo "====================================================="
echo "  Objective 2 — Environment Setup"
echo "====================================================="
echo ""

# ----------------------------------------------------------
# 1. Python dependencies (system / active env — no venv)
# ----------------------------------------------------------
echo "[1/5] Installing Python dependencies ..."
python3 -m pip install --upgrade pip -q
python3 -m pip install \
    python-dotenv \
    kafka-python \
    redis \
    requests \
    cryptography \
    ecdsa \
    grpcio \
    protobuf \
    fastapi \
    uvicorn \
    pydantic \
    httpx \
    -q
echo "      ✔ Python deps installed"

# ----------------------------------------------------------
# 2. Create project.env from example if not already present
# ----------------------------------------------------------
echo "[2/5] Checking project.env ..."
if [ ! -f "$REPO_ROOT/project.env" ]; then
    if [ -f "$REPO_ROOT/project.env.example" ]; then
        cp "$REPO_ROOT/project.env.example" "$REPO_ROOT/project.env"
        echo "      ✔ Created project.env from project.env.example"
    else
        echo "      ✔ project.env already committed directly"
    fi
else
    echo "      ✔ project.env already exists — skipping"
fi

# ----------------------------------------------------------
# 3. fabric-samples  (clone if missing, set PATH + env vars)
# ----------------------------------------------------------
echo "[3/5] Checking fabric-samples ..."
FABRIC_SAMPLES_DIR="$REPO_ROOT/fabric-samples"
if [ ! -d "$FABRIC_SAMPLES_DIR/bin" ]; then
    echo "      fabric-samples/bin not found — cloning ..."
    git clone --depth 1 https://github.com/hyperledger/fabric-samples.git "$FABRIC_SAMPLES_DIR" 2>/dev/null || true
    if [ ! -d "$FABRIC_SAMPLES_DIR/bin" ]; then
        echo "      Downloading Fabric binaries via install script ..."
        curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.9 1.5.7 -d -s 2>/dev/null || true
    fi
fi

if [ -d "$FABRIC_SAMPLES_DIR/bin" ]; then
    echo "      ✔ fabric-samples/bin present"
    # Persist to project.env if not already there
    if ! grep -q 'FABRIC_BIN_DIR' "$REPO_ROOT/project.env" 2>/dev/null; then
        echo "FABRIC_BIN_DIR=$FABRIC_SAMPLES_DIR/bin" >> "$REPO_ROOT/project.env"
    fi
    if ! grep -q 'FABRIC_CFG_PATH' "$REPO_ROOT/project.env" 2>/dev/null; then
        echo "FABRIC_CFG_PATH=$FABRIC_SAMPLES_DIR/config" >> "$REPO_ROOT/project.env"
    fi
else
    echo "      ⚠  fabric-samples/bin still missing. run.py will create a minimal core.yaml fallback."
fi

# ----------------------------------------------------------
# 4. Go module for chaincode
# ----------------------------------------------------------
echo "[4/5] Initialising Go chaincode module ..."
if [ -f "$REPO_ROOT/chaincode/security_logger.go" ]; then
    cd "$REPO_ROOT/chaincode"
    if [ ! -f go.mod ]; then
        go mod init security_logger 2>/dev/null || true
        go get github.com/hyperledger/fabric-contract-api-go/contractapi@latest 2>/dev/null || true
        go mod tidy 2>/dev/null || true
        echo "      ✔ go.mod created"
    else
        echo "      ✔ go.mod already exists"
    fi
    cd "$REPO_ROOT"
else
    echo "      ⚠  chaincode/security_logger.go not found — skipping go mod"
fi

# ----------------------------------------------------------
# 5. activate_project.sh  (convenience helper)
# ----------------------------------------------------------
echo "[5/5] Writing activate_project.sh ..."
cat > "$REPO_ROOT/activate_project.sh" << 'ACTIVATE_EOF'
#!/usr/bin/env bash
# Source this file at the start of every session:
#   source ./activate_project.sh
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FABRIC_SAMPLES_DIR="$REPO_ROOT/fabric-samples"
if [ -d "$FABRIC_SAMPLES_DIR/bin" ]; then
    export PATH="$FABRIC_SAMPLES_DIR/bin:$PATH"
    export FABRIC_CFG_PATH="$FABRIC_SAMPLES_DIR/config"
fi
if [ -f "$REPO_ROOT/project.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_ROOT/project.env"
    set +a
fi
echo "[obj2] Environment loaded. Run: python3 run.py"
ACTIVATE_EOF
chmod +x "$REPO_ROOT/activate_project.sh"
echo "      ✔ activate_project.sh written"

# ----------------------------------------------------------
echo ""
echo "====================================================="
echo "  Setup complete!"
echo ""
echo "  Next steps:"
echo "    source ./activate_project.sh   # load env vars"
echo "    python3 run.py                 # full live run"
echo "====================================================="
echo ""
