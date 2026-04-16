#!/usr/bin/env bash
# Run the full 15M episode campaign across all profiles.
#
# This script runs the campaign in shards — one profile at a time —
# so that partial results are saved even if the pod is interrupted.
#
# Expected runtime: 4-8 hours on RunPod (depends on GPU/CPU).
# Expected output: ~2-5 GB of JSON results.
#
# Usage:
#   bash scripts/run_15m_campaign.sh

set -euo pipefail

CAMPAIGN_NAME="invariant_15m_proof_$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="results/${CAMPAIGN_NAME}"
STEPS_PER_EPISODE=200
LOG_FILE="${OUTPUT_DIR}/campaign.log"

# Episode distribution per profile (totals ~15M across 13 profiles).
# Weighted by deployment risk per spec-15m-campaign.md.
declare -A EPISODES_PER_PROFILE=(
    ["humanoid_28dof"]=1800000
    ["unitree_h1"]=1200000
    ["unitree_g1"]=1200000
    ["ur10e_haas_cell"]=1500000
    ["ur10e_cnc_tending"]=1200000
    ["franka_panda"]=1200000
    ["kuka_iiwa14"]=900000
    ["kinova_gen3"]=750000
    ["abb_gofa"]=750000
    ["spot"]=1200000
    ["quadruped_12dof"]=750000
    ["shadow_hand"]=750000
    ["ur10"]=600000
)

mkdir -p "${OUTPUT_DIR}"

echo "============================================================" | tee "${LOG_FILE}"
echo "INVARIANT 15M CAMPAIGN: ${CAMPAIGN_NAME}" | tee -a "${LOG_FILE}"
echo "============================================================" | tee -a "${LOG_FILE}"
echo "Started: $(date -u)" | tee -a "${LOG_FILE}"
echo "Output:  ${OUTPUT_DIR}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

TOTAL_EPISODES=0
for ep in "${EPISODES_PER_PROFILE[@]}"; do
    TOTAL_EPISODES=$((TOTAL_EPISODES + ep))
done
echo "Total episodes: ${TOTAL_EPISODES}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

# Ensure binary exists.
if [ ! -x "target/release/invariant" ]; then
    echo "Building Invariant..." | tee -a "${LOG_FILE}"
    cargo build --release 2>&1 | tail -3 | tee -a "${LOG_FILE}"
fi

# Generate keys if needed.
if [ ! -f "keys.json" ]; then
    echo "Generating keys..." | tee -a "${LOG_FILE}"
    ./target/release/invariant keygen --kid "${CAMPAIGN_NAME}" --output keys.json
fi

# Run each profile as a separate shard.
COMPLETED=0
FAILED=0
for PROFILE in "${!EPISODES_PER_PROFILE[@]}"; do
    EPISODES="${EPISODES_PER_PROFILE[$PROFILE]}"
    SHARD_OUTPUT="${OUTPUT_DIR}/${PROFILE}"
    mkdir -p "${SHARD_OUTPUT}"

    echo "---" | tee -a "${LOG_FILE}"
    echo "Profile: ${PROFILE} (${EPISODES} episodes)" | tee -a "${LOG_FILE}"
    echo "Started: $(date -u)" | tee -a "${LOG_FILE}"

    if python isaac/campaign_runner.py \
        --name "${CAMPAIGN_NAME}_${PROFILE}" \
        --episodes "${EPISODES}" \
        --steps "${STEPS_PER_EPISODE}" \
        --profile "${PROFILE}" \
        --output "${SHARD_OUTPUT}" \
        -v 2>&1 | tee -a "${LOG_FILE}"; then
        echo "Profile ${PROFILE}: PASSED" | tee -a "${LOG_FILE}"
        COMPLETED=$((COMPLETED + 1))
    else
        echo "Profile ${PROFILE}: FAILED (exit code $?)" | tee -a "${LOG_FILE}"
        FAILED=$((FAILED + 1))
    fi

    echo "Finished: $(date -u)" | tee -a "${LOG_FILE}"
done

# Summary.
echo "" | tee -a "${LOG_FILE}"
echo "============================================================" | tee -a "${LOG_FILE}"
echo "CAMPAIGN COMPLETE" | tee -a "${LOG_FILE}"
echo "============================================================" | tee -a "${LOG_FILE}"
echo "Profiles completed: ${COMPLETED}/13" | tee -a "${LOG_FILE}"
echo "Profiles failed:    ${FAILED}/13" | tee -a "${LOG_FILE}"
echo "Results in:         ${OUTPUT_DIR}" | tee -a "${LOG_FILE}"
echo "Finished:           $(date -u)" | tee -a "${LOG_FILE}"

if [ "${FAILED}" -gt 0 ]; then
    echo ""
    echo "WARNING: ${FAILED} profile(s) failed. Check ${LOG_FILE} for details."
    exit 1
fi

echo ""
echo "Upload to HuggingFace:"
echo "  python scripts/upload_results.py --dir ${OUTPUT_DIR} --repo invariant-15m-proof"
