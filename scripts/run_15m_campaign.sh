#!/usr/bin/env bash
# Run the full 15M episode campaign across all 34 profiles.
#
# This script runs the campaign in shards -- one profile at a time --
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

# Episode distribution per profile (totals ~15M across 34 profiles).
# Weighted by deployment risk per spec-15m-campaign.md.
declare -A EPISODES_PER_PROFILE=(
    # Humanoids (11) -- highest priority
    ["humanoid_28dof"]=900000
    ["unitree_h1"]=750000
    ["unitree_g1"]=600000
    ["fourier_gr1"]=600000
    ["tesla_optimus"]=600000
    ["figure_02"]=600000
    ["bd_atlas"]=600000
    ["agility_digit"]=450000
    ["sanctuary_phoenix"]=450000
    ["onex_neo"]=450000
    ["apptronik_apollo"]=450000
    # Quadrupeds (5)
    ["quadruped_12dof"]=450000
    ["spot"]=600000
    ["unitree_go2"]=450000
    ["unitree_a1"]=300000
    ["anybotics_anymal"]=300000
    # Arms (7)
    ["franka_panda"]=600000
    ["ur10"]=450000
    ["ur10e_haas_cell"]=600000
    ["ur10e_cnc_tending"]=600000
    ["kuka_iiwa14"]=450000
    ["kinova_gen3"]=300000
    ["abb_gofa"]=300000
    # Dexterous hands (4)
    ["shadow_hand"]=300000
    ["allegro_hand"]=300000
    ["leap_hand"]=150000
    ["psyonic_ability"]=150000
    # Mobile manipulators (3)
    ["spot_with_arm"]=450000
    ["hello_stretch"]=300000
    ["pal_tiago"]=300000
    # Adversarial (4)
    ["adversarial_zero_margin"]=300000
    ["adversarial_max_workspace"]=300000
    ["adversarial_single_joint"]=300000
    ["adversarial_max_joints"]=300000
)

NUM_PROFILES=${#EPISODES_PER_PROFILE[@]}

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
echo "Total episodes: ${TOTAL_EPISODES} across ${NUM_PROFILES} profiles" | tee -a "${LOG_FILE}"
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
echo "Profiles completed: ${COMPLETED}/${NUM_PROFILES}" | tee -a "${LOG_FILE}"
echo "Profiles failed:    ${FAILED}/${NUM_PROFILES}" | tee -a "${LOG_FILE}"
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
