#!/usr/bin/env bash
# RunPod setup script — run this in the pod's terminal.
#
# This script installs Rust, builds Invariant, and prepares the environment
# for running Isaac Lab campaigns. Use this when you're NOT using the Docker
# image (e.g., on a RunPod template like "RunPod Pytorch 2.1").
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/clay-good/invariant/main/scripts/runpod_setup.sh | bash
#   # or:
#   git clone https://github.com/clay-good/invariant.git && cd invariant && bash scripts/runpod_setup.sh

set -euo pipefail

echo "=== Invariant RunPod Setup ==="
echo "Started: $(date -u)"

# ---------------------------------------------------------------------------
# 1. Install Rust (if not present)
# ---------------------------------------------------------------------------
if ! command -v cargo &>/dev/null; then
    echo ">>> Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo ">>> Rust already installed: $(rustc --version)"
fi

# ---------------------------------------------------------------------------
# 2. Clone repo (if not already in it)
# ---------------------------------------------------------------------------
if [ ! -f "Cargo.toml" ]; then
    echo ">>> Cloning Invariant repository..."
    git clone https://github.com/clay-good/invariant.git
    cd invariant
fi

# ---------------------------------------------------------------------------
# 3. Build release binary
# ---------------------------------------------------------------------------
echo ">>> Building Invariant (release mode)..."
cargo build --release 2>&1 | tail -5

echo ">>> Binary: $(ls -lh target/release/invariant)"

# ---------------------------------------------------------------------------
# 4. Quick sanity test
# ---------------------------------------------------------------------------
echo ">>> Running test suite..."
TEST_OUTPUT=$(cargo test 2>&1 | tail -1)
echo ">>> $TEST_OUTPUT"

# ---------------------------------------------------------------------------
# 5. Generate campaign keys
# ---------------------------------------------------------------------------
echo ">>> Generating campaign keys..."
./target/release/invariant keygen --kid "runpod-campaign" --output keys.json
echo ">>> Keys: keys.json"

# ---------------------------------------------------------------------------
# 6. Install Python deps
# ---------------------------------------------------------------------------
echo ">>> Installing Python dependencies..."
pip install --quiet huggingface_hub 2>/dev/null || true

# ---------------------------------------------------------------------------
# 7. Create results directory
# ---------------------------------------------------------------------------
mkdir -p results

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Quick test (100 episodes, 1 profile, ~30 seconds):"
echo "  python isaac/campaign_runner.py --episodes 100 --steps 200 --profile ur10e_cnc_tending -v"
echo ""
echo "Full campaign (all 34 profiles, 100 episodes each):"
echo "  python isaac/campaign_runner.py --episodes 100 --steps 200 --all-profiles -v"
echo ""
echo "15M campaign (use scripts/run_15m_campaign.sh):"
echo "  bash scripts/run_15m_campaign.sh"
echo ""
