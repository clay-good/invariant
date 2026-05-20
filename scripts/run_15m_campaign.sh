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
#
# Environment variables (v12-N-7):
#   MAX_USD       Hard ceiling on projected total spend in USD. Default 40.
#                 Set to 0 for a dry-run abort that verifies wiring without
#                 starting any shard.
#   HOURLY_USD    Operator's per-hour cost assumption. Default 2.50 (RunPod
#                 RTX 4090 ballpark). Document the assumed rate alongside the
#                 invocation so it can be reconciled against the invoice.
#   RESUME_DIR    If set, scan this directory for `<profile>.complete` and
#                 `<profile>.in-progress.json` markers and resume from there
#                 instead of starting a fresh campaign.

set -euo pipefail

CAMPAIGN_NAME="invariant_15m_proof_$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${RESUME_DIR:-results/${CAMPAIGN_NAME}}"
STEPS_PER_EPISODE=200
LOG_FILE="${OUTPUT_DIR}/campaign.log"

MAX_USD="${MAX_USD:-40}"
HOURLY_USD="${HOURLY_USD:-2.50}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAMPAIGN_START_EPOCH=$(date +%s)

# SIGTERM / SIGINT trap: flush an in-progress marker for the active shard and
# exit 130 so the pod restarts cleanly. The marker is what RESUME_DIR scans on
# startup to skip completed shards and resume incomplete ones.
CURRENT_SHARD=""
on_termination() {
    if [[ -n "${CURRENT_SHARD}" ]]; then
        local marker="${OUTPUT_DIR}/${CURRENT_SHARD}.in-progress.json"
        printf '{"profile":"%s","interrupted_at":"%s","signal":"TERM_OR_INT"}\n' \
            "${CURRENT_SHARD}" "$(date -u +%FT%TZ)" > "${marker}"
        echo "[v12-N-7] flushed in-progress marker for ${CURRENT_SHARD}: ${marker}" \
            | tee -a "${LOG_FILE}" >&2 || true
    fi
    exit 130
}
trap on_termination SIGTERM SIGINT

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
SKIPPED=0
ABORTED_FOR_COST=0
SHARD_INDEX=0
for PROFILE in "${!EPISODES_PER_PROFILE[@]}"; do
    SHARD_INDEX=$((SHARD_INDEX + 1))
    EPISODES="${EPISODES_PER_PROFILE[$PROFILE]}"
    SHARD_OUTPUT="${OUTPUT_DIR}/${PROFILE}"
    COMPLETE_MARKER="${OUTPUT_DIR}/${PROFILE}.complete"
    IN_PROGRESS_MARKER="${OUTPUT_DIR}/${PROFILE}.in-progress.json"

    # Resume support: skip shards already marked complete (v12-N-7).
    if [[ -f "${COMPLETE_MARKER}" ]]; then
        echo "[resume] skipping ${PROFILE}: complete marker present" | tee -a "${LOG_FILE}"
        SKIPPED=$((SKIPPED + 1))
        COMPLETED=$((COMPLETED + 1))
        continue
    fi
    if [[ -f "${IN_PROGRESS_MARKER}" ]]; then
        echo "[resume] resuming ${PROFILE}: in-progress marker found at ${IN_PROGRESS_MARKER}" \
            | tee -a "${LOG_FILE}"
        # The campaign_runner is responsible for picking up partial state in
        # SHARD_OUTPUT. We leave the marker in place; it is overwritten on
        # successful completion (below) or refreshed by another SIGTERM.
    fi

    # Cost ceiling (v12-N-7): project final spend before starting each shard.
    # fraction_complete uses the shard index as a proxy; once a real-time
    # billing API is wired we can swap in actual usage.
    FRACTION_COMPLETE=$(awk -v idx="${SHARD_INDEX}" -v n="${NUM_PROFILES}" \
        'BEGIN { f = (idx - 1) / n; if (f <= 0) { f = 1 / (n + 1) }; printf "%.6f", f }')
    NOW_EPOCH=$(date +%s)
    ELAPSED=$((NOW_EPOCH - CAMPAIGN_START_EPOCH))
    if ! python3 "${SCRIPT_DIR}/check_spend.py" \
        --elapsed-seconds "${ELAPSED}" \
        --fraction-complete "${FRACTION_COMPLETE}" \
        --hourly-usd "${HOURLY_USD}" \
        --max-usd "${MAX_USD}" 2>&1 | tee -a "${LOG_FILE}"; then
        echo "[cost] ABORT before ${PROFILE}: projected spend exceeds MAX_USD=\$${MAX_USD}" \
            | tee -a "${LOG_FILE}"
        ABORTED_FOR_COST=$((ABORTED_FOR_COST + 1))
        break
    fi

    mkdir -p "${SHARD_OUTPUT}"
    CURRENT_SHARD="${PROFILE}"
    # Pre-emptively write an in-progress marker so a hard SIGKILL (which
    # cannot be trapped) still leaves a recoverable trace.
    printf '{"profile":"%s","started_at":"%s"}\n' \
        "${PROFILE}" "$(date -u +%FT%TZ)" > "${IN_PROGRESS_MARKER}"

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
        # Atomically promote in-progress → complete marker.
        printf '{"profile":"%s","completed_at":"%s","episodes":%s}\n' \
            "${PROFILE}" "$(date -u +%FT%TZ)" "${EPISODES}" > "${COMPLETE_MARKER}"
        rm -f "${IN_PROGRESS_MARKER}"
    else
        EXIT_CODE=$?
        echo "Profile ${PROFILE}: FAILED (exit code ${EXIT_CODE})" | tee -a "${LOG_FILE}"
        FAILED=$((FAILED + 1))
        # Leave the in-progress marker for resume; do NOT remove on failure.
    fi
    CURRENT_SHARD=""

    echo "Finished: $(date -u)" | tee -a "${LOG_FILE}"
done

# Summary.
echo "" | tee -a "${LOG_FILE}"
echo "============================================================" | tee -a "${LOG_FILE}"
echo "CAMPAIGN COMPLETE" | tee -a "${LOG_FILE}"
echo "============================================================" | tee -a "${LOG_FILE}"
echo "Profiles completed: ${COMPLETED}/${NUM_PROFILES} (resumed ${SKIPPED})" | tee -a "${LOG_FILE}"
echo "Profiles failed:    ${FAILED}/${NUM_PROFILES}" | tee -a "${LOG_FILE}"
echo "Aborted for cost:   ${ABORTED_FOR_COST}" | tee -a "${LOG_FILE}"
echo "Results in:         ${OUTPUT_DIR}" | tee -a "${LOG_FILE}"
echo "Finished:           $(date -u)" | tee -a "${LOG_FILE}"

if [ "${ABORTED_FOR_COST}" -gt 0 ]; then
    echo ""
    echo "WARNING: campaign aborted because projected spend exceeded MAX_USD=\$${MAX_USD}." \
        "Re-run with RESUME_DIR=${OUTPUT_DIR} after raising MAX_USD."
    exit 2
fi

if [ "${FAILED}" -gt 0 ]; then
    echo ""
    echo "WARNING: ${FAILED} profile(s) failed. Check ${LOG_FILE} for details."
    exit 1
fi

echo ""
echo "Upload to HuggingFace:"
echo "  python scripts/upload_results.py --dir ${OUTPUT_DIR} --repo invariant-15m-proof"
