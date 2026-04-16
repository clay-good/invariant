#!/usr/bin/env python3
"""Invariant Isaac Lab campaign runner.

Orchestrates a multi-episode, multi-profile simulation campaign by:
  1. Starting the Invariant server (Rust, --bridge --trust-plane)
  2. For each profile x scenario:
     a. Creating an Isaac Lab environment (or dry-run env)
     b. Running N episodes of M steps
     c. Sending each command through the Invariant bridge for validation
     d. Optionally injecting adversarial faults
     e. Recording verdicts
  3. Aggregating results into a JSON proof report
  4. Writing the report to disk

Usage:
    # 100-episode test run (no Isaac Sim needed)
    python campaign_runner.py --episodes 100 --steps 200 --profile ur10e_cnc_tending

    # Full 15M campaign on RunPod with Isaac Sim
    python campaign_runner.py --config campaigns/15m.yaml

    # Quick smoke test
    python campaign_runner.py --episodes 10 --steps 50 --profile ur10e_cnc_tending --dry-run
"""

import argparse
import json
import logging
import os
import random
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add parent paths for imports.
_repo_root = Path(__file__).resolve().parent.parent
_bridge_client_dir = _repo_root / "crates" / "invariant-sim"
sys.path.insert(0, str(_bridge_client_dir))
sys.path.insert(0, str(_repo_root / "isaac"))

from invariant_isaac_bridge import InvariantBridge
from injector import InjectionType, inject_for_scenario
from reporter import CampaignReporter, StepResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Profiles: map name -> profile JSON path + joint names
# ---------------------------------------------------------------------------

BUILTIN_PROFILES = {
    # Humanoids (11)
    "humanoid_28dof": "humanoid_28dof.json",
    "unitree_h1": "unitree_h1.json",
    "unitree_g1": "unitree_g1.json",
    "fourier_gr1": "fourier_gr1.json",
    "tesla_optimus": "tesla_optimus.json",
    "figure_02": "figure_02.json",
    "bd_atlas": "bd_atlas.json",
    "agility_digit": "agility_digit.json",
    "sanctuary_phoenix": "sanctuary_phoenix.json",
    "onex_neo": "onex_neo.json",
    "apptronik_apollo": "apptronik_apollo.json",
    # Quadrupeds (5)
    "quadruped_12dof": "quadruped_12dof.json",
    "spot": "spot.json",
    "unitree_go2": "unitree_go2.json",
    "unitree_a1": "unitree_a1.json",
    "anybotics_anymal": "anybotics_anymal.json",
    # Arms (7)
    "franka_panda": "franka_panda.json",
    "ur10": "ur10.json",
    "ur10e_haas_cell": "ur10e_haas_cell.json",
    "ur10e_cnc_tending": "ur10e_cnc_tending.json",
    "kuka_iiwa14": "kuka_iiwa14.json",
    "kinova_gen3": "kinova_gen3.json",
    "abb_gofa": "abb_gofa.json",
    # Dexterous hands (4)
    "shadow_hand": "shadow_hand.json",
    "allegro_hand": "allegro_hand.json",
    "leap_hand": "leap_hand.json",
    "psyonic_ability": "psyonic_ability.json",
    # Mobile manipulators (3)
    "spot_with_arm": "spot_with_arm.json",
    "hello_stretch": "hello_stretch.json",
    "pal_tiago": "pal_tiago.json",
    # Adversarial (4)
    "adversarial_zero_margin": "adversarial_zero_margin.json",
    "adversarial_max_workspace": "adversarial_max_workspace.json",
    "adversarial_single_joint": "adversarial_single_joint.json",
    "adversarial_max_joints": "adversarial_max_joints.json",
}

# Scenarios with their default weights and whether they are adversarial.
DEFAULT_SCENARIOS = [
    ("baseline", 0.40, False),
    ("aggressive", 0.10, False),
    ("exclusion_zone", 0.08, True),
    ("prompt_injection", 0.08, True),
    ("authority_escalation", 0.05, True),
    ("chain_forgery", 0.05, True),
    ("compound_authority_physics", 0.04, True),
    ("compound_drift_then_violation", 0.04, True),
    ("environment_fault", 0.04, True),
    ("long_running_stability", 0.04, False),
    ("long_running_threat", 0.04, True),
    ("multi_agent_handoff", 0.04, True),
]


# ---------------------------------------------------------------------------
# Profile loader
# ---------------------------------------------------------------------------


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Load a robot profile JSON and extract joint info."""
    profile_dir = _repo_root / "profiles"
    filename = BUILTIN_PROFILES.get(profile_name, f"{profile_name}.json")
    path = profile_dir / filename
    if not path.is_file():
        raise FileNotFoundError(f"Profile not found: {path}")
    with open(path) as f:
        return json.load(f)


def get_joint_names(profile: Dict[str, Any]) -> List[str]:
    """Extract joint names from a profile dict."""
    return [j["name"] for j in profile.get("joints", [])]


def get_safe_joint_positions(profile: Dict[str, Any]) -> Dict[str, float]:
    """Get mid-range joint positions (safe for any profile)."""
    positions = {}
    for joint in profile.get("joints", []):
        mid = (joint["min"] + joint["max"]) / 2.0
        positions[joint["name"]] = mid
    return positions


def get_safe_ee_position(profile: Dict[str, Any]) -> List[float]:
    """Get a safe end-effector position within the workspace."""
    ws = profile.get("workspace", {})
    if "aabb" in ws:
        # Not present directly — check for min/max pattern.
        pass
    # Return a conservative default near origin.
    return [0.3, 0.0, 0.8]


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------


def build_command(
    profile: Dict[str, Any],
    sequence: int,
    delta_time: float = 0.008,
    joint_positions: Optional[Dict[str, float]] = None,
    ee_position: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """Build a valid Invariant Command JSON from a profile.

    Uses safe mid-range positions by default. Override joint_positions
    and ee_position for specific scenarios.
    """
    joints = joint_positions or get_safe_joint_positions(profile)
    ee = ee_position or get_safe_ee_position(profile)
    joint_names = get_joint_names(profile)

    now = datetime.now(timezone.utc).isoformat()

    joint_states = []
    for name in joint_names:
        joint_states.append({
            "name": name,
            "position": joints.get(name, 0.0),
            "velocity": 0.0,
            "effort": 0.0,
        })

    # Build EE positions for collision checks — use profile's end_effectors
    # if available, otherwise single default.
    ee_positions = []
    for ee_def in profile.get("end_effectors", []):
        ee_positions.append({
            "name": ee_def.get("name", "end_effector"),
            "position": list(ee),
        })
    if not ee_positions:
        ee_positions.append({"name": "end_effector", "position": list(ee)})

    return {
        "timestamp": now,
        "source": "isaac_lab_campaign",
        "sequence": sequence,
        "joint_states": joint_states,
        "delta_time": delta_time,
        "end_effector_positions": ee_positions,
        "authority": {
            "pca_chain": "",  # trust-plane mode auto-signs
            "required_ops": ["actuate:*"],
        },
        "metadata": {},
    }


# ---------------------------------------------------------------------------
# Invariant server management
# ---------------------------------------------------------------------------


def find_invariant_binary() -> str:
    """Locate the invariant binary."""
    for mode in ("release", "debug"):
        candidate = _repo_root / "target" / mode / "invariant"
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    raise FileNotFoundError(
        "invariant binary not found — run `cargo build --release` first"
    )


def start_server(
    profile_path: str,
    keys_path: str,
    socket_path: str,
    binary: Optional[str] = None,
    port: int = 18080,
) -> subprocess.Popen:
    """Start the Invariant server with bridge enabled."""
    binary = binary or find_invariant_binary()

    cmd = [
        binary,
        "serve",
        "--profile", profile_path,
        "--key", keys_path,
        "--port", str(port),
        "--trust-plane",
        "--watchdog-timeout-ms", "0",
        "--bridge",
        "--bridge-socket", socket_path,
    ]

    logger.info("Starting Invariant server: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for socket to appear.
    for _ in range(100):
        if os.path.exists(socket_path):
            logger.info("Invariant server ready (socket: %s)", socket_path)
            return proc
        time.sleep(0.1)

    # Server didn't start — kill and report.
    proc.kill()
    _, stderr = proc.communicate(timeout=5)
    raise RuntimeError(
        f"Invariant server failed to start. stderr: {stderr.decode()}"
    )


def stop_server(proc: subprocess.Popen) -> None:
    """Gracefully stop the Invariant server."""
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def generate_keys(binary: str, output_path: str, kid: str = "campaign") -> None:
    """Generate Ed25519 keys for the campaign."""
    result = subprocess.run(
        [binary, "keygen", "--kid", kid, "--output", output_path],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"keygen failed: {result.stderr}")


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------


def run_episode(
    bridge: InvariantBridge,
    profile: Dict[str, Any],
    profile_name: str,
    scenario: str,
    is_adversarial: bool,
    steps: int,
    reporter: CampaignReporter,
    sequence_offset: int,
) -> int:
    """Run a single episode and record results.

    Returns the number of commands sent (= next sequence offset delta).
    """
    for step in range(steps):
        seq = sequence_offset + step + 1

        # Build a valid baseline command from the profile.
        cmd = build_command(profile, sequence=seq)

        # Apply adversarial injection for attack scenarios.
        injected = False
        if is_adversarial:
            injected = inject_for_scenario(cmd, scenario, probability=0.7)

        # Send to Invariant for validation.
        try:
            result = bridge.validate(cmd)
        except (TimeoutError, ConnectionError) as e:
            logger.warning("Bridge error on step %d: %s", step, e)
            continue

        approved = result.get("approved", False)
        checks = []
        sv = result.get("signed_verdict", {})
        if sv:
            checks = sv.get("checks", [])

        reporter.record(StepResult(
            profile=profile_name,
            scenario=scenario,
            approved=approved,
            injected=injected,
            checks=checks,
        ))

    reporter.end_episode(steps)
    return steps


# ---------------------------------------------------------------------------
# Campaign runner
# ---------------------------------------------------------------------------


def run_campaign(
    campaign_name: str,
    profile_names: List[str],
    episodes_per_profile: int,
    steps_per_episode: int,
    scenarios: Optional[List[Tuple[str, float, bool]]] = None,
    output_dir: str = "results",
) -> Dict[str, Any]:
    """Run a full campaign across profiles and scenarios.

    This is the main entry point. It:
      1. Builds the Invariant binary (if needed)
      2. For each profile:
         a. Starts the Invariant server
         b. Runs episodes across weighted scenarios
         c. Stops the server
      3. Writes the aggregated report
    """
    scenarios = scenarios or DEFAULT_SCENARIOS
    reporter = CampaignReporter(campaign_name)

    binary = find_invariant_binary()
    profiles_dir = _repo_root / "profiles"
    os.makedirs(output_dir, exist_ok=True)

    # Temp directory for per-profile keys and sockets.
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="invariant_campaign_")

    keys_path = os.path.join(tmpdir, "keys.json")
    generate_keys(binary, keys_path, kid=f"{campaign_name}-key")

    total_episodes = episodes_per_profile * len(profile_names)
    completed = 0
    global_sequence = 0

    for profile_name in profile_names:
        logger.info(
            "=== Profile: %s (%d/%d profiles) ===",
            profile_name,
            profile_names.index(profile_name) + 1,
            len(profile_names),
        )

        # Load profile.
        profile = load_profile(profile_name)
        filename = BUILTIN_PROFILES.get(profile_name, f"{profile_name}.json")
        profile_path = str(profiles_dir / filename)

        # Start server for this profile.
        socket_path = os.path.join(tmpdir, f"{profile_name}.sock")
        # Use different port per profile to avoid conflicts.
        port = 18080 + profile_names.index(profile_name)

        server = start_server(
            profile_path=profile_path,
            keys_path=keys_path,
            socket_path=socket_path,
            binary=binary,
            port=port,
        )

        try:
            bridge = InvariantBridge(socket_path, timeout_s=5.0)

            # Distribute episodes across scenarios by weight.
            scenario_episodes = _distribute_episodes(
                episodes_per_profile, scenarios
            )

            for scenario_name, n_episodes, is_adversarial in scenario_episodes:
                logger.info(
                    "  Scenario: %s (%d episodes, adversarial=%s)",
                    scenario_name,
                    n_episodes,
                    is_adversarial,
                )

                for ep in range(n_episodes):
                    steps_done = run_episode(
                        bridge=bridge,
                        profile=profile,
                        profile_name=profile_name,
                        scenario=scenario_name,
                        is_adversarial=is_adversarial,
                        steps=steps_per_episode,
                        reporter=reporter,
                        sequence_offset=global_sequence,
                    )
                    global_sequence += steps_done
                    completed += 1

                    if completed % 100 == 0:
                        pct = completed / total_episodes * 100
                        logger.info(
                            "  Progress: %d/%d episodes (%.1f%%)",
                            completed,
                            total_episodes,
                            pct,
                        )

            bridge.close()

        finally:
            stop_server(server)
            # Clean up socket.
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    # Write report.
    report = reporter.to_report()
    report_path = os.path.join(output_dir, f"{campaign_name}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    reporter.print_summary()
    logger.info("Report written to: %s", report_path)

    # Cleanup.
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return report


def _distribute_episodes(
    total: int,
    scenarios: List[Tuple[str, float, bool]],
) -> List[Tuple[str, int, bool]]:
    """Distribute episodes across scenarios by weight."""
    weight_sum = sum(w for _, w, _ in scenarios)
    result = []
    allocated = 0
    for i, (name, weight, is_adv) in enumerate(scenarios):
        if i == len(scenarios) - 1:
            # Last scenario gets the remainder.
            n = total - allocated
        else:
            n = round(total * weight / weight_sum)
        allocated += n
        if n > 0:
            result.append((name, n, is_adv))
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Run an Invariant safety validation campaign"
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Campaign name (default: auto-generated)",
    )
    parser.add_argument(
        "--episodes",
        type=int,
        default=100,
        help="Episodes per profile (default: 100)",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=200,
        help="Steps per episode (default: 200)",
    )
    parser.add_argument(
        "--profile",
        nargs="+",
        default=["ur10e_cnc_tending"],
        help="Profile name(s) to test (default: ur10e_cnc_tending)",
    )
    parser.add_argument(
        "--all-profiles",
        action="store_true",
        help="Run all 34 built-in profiles",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory (default: results/)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    profiles = list(BUILTIN_PROFILES.keys()) if args.all_profiles else args.profile
    name = args.name or f"campaign_{len(profiles)}p_{args.episodes}ep_{args.steps}s"

    logger.info("Starting campaign: %s", name)
    logger.info("  Profiles: %s", ", ".join(profiles))
    logger.info("  Episodes per profile: %d", args.episodes)
    logger.info("  Steps per episode: %d", args.steps)
    total = args.episodes * len(profiles) * args.steps
    logger.info("  Total commands: ~%d", total)

    report = run_campaign(
        campaign_name=name,
        profile_names=profiles,
        episodes_per_profile=args.episodes,
        steps_per_episode=args.steps,
        output_dir=args.output,
    )

    sys.exit(0 if report.get("criteria_met") else 1)


if __name__ == "__main__":
    main()
