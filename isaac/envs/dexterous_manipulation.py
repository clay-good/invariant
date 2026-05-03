"""Dexterous manipulation environment for the 15M campaign (A-07).

File: isaac/envs/dexterous_manipulation.py
Spec: A-07 — Dexterous Manipulation (300 steps x 300,000 episodes)

High-DOF dexterous manipulation with independent per-finger sinusoidal
sweeps covering nearly the full joint range. Tests that the firewall
handles many joints moving at different phases simultaneously without
false positives.

Profile subset: shadow_hand, kinova_gen3, franka_panda.

Invariants exercised (pass path): P1, P2, P3, P4, P5; A1, A2, A3.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROFILES_DIR = _REPO_ROOT / "profiles"

DEXTEROUS_PROFILES = ["shadow_hand", "kinova_gen3", "franka_panda"]
STEPS_PER_EPISODE = 300
EPISODES_TOTAL = 300_000
EPISODES_PER_PROFILE = EPISODES_TOTAL // len(DEXTEROUS_PROFILES)

DEFAULT_MARGINS = {
    "position_margin": 0.05,
    "velocity_margin": 0.10,
    "torque_margin": 0.10,
}


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Load a profile JSON from the profiles directory."""
    path = _PROFILES_DIR / f"{profile_name}.json"
    with open(path) as f:
        return json.load(f)


def get_margins(profile: Dict[str, Any]) -> Dict[str, float]:
    """Extract real-world margins, falling back to defaults."""
    rwm = profile.get("real_world_margins", {})
    return {
        "position_margin": rwm.get(
            "position_margin", DEFAULT_MARGINS["position_margin"]
        ),
        "velocity_margin": rwm.get(
            "velocity_margin", DEFAULT_MARGINS["velocity_margin"]
        ),
        "torque_margin": rwm.get(
            "torque_margin", DEFAULT_MARGINS["torque_margin"]
        ),
    }


def generate_dexterous_command(
    profile: Dict[str, Any],
    step_index: int,
    total_steps: int,
    sequence: int,
    proximity_scale: float = 1.0,
) -> Dict[str, Any]:
    """Generate a single dexterous manipulation command per the A-07 spec.

    Each joint runs at a distinct sinusoidal frequency so the command
    stream exercises all possible inter-joint phase relationships. The
    85% amplitude keeps positions inside effective limits even with
    floating-point rounding.

    Args:
        profile: Loaded profile dict.
        step_index: Current step (0-based).
        total_steps: Total steps in the episode.
        sequence: Monotonic sequence number.
        proximity_scale: Velocity scaling from proximity zones (0.0-1.0).

    Returns:
        A valid Invariant Command JSON dict.
    """
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)
    delta_time = 0.5 * max_delta_time

    joints = profile["joints"]
    joint_states = []

    for j, joint in enumerate(joints):
        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        max_vel = joint["max_velocity"]
        max_torque = joint["max_torque"]

        # Effective range after margin tightening
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin
        eff_range = eff_max - eff_min
        mid = (eff_min + eff_max) / 2.0
        half_range = eff_range / 2.0

        # Per-joint sinusoidal sweep
        f_j = 1.0 + j * 0.3
        phi_j = (step_index / total_steps) * 2.0 * math.pi * f_j

        position = mid + half_range * 0.85 * math.sin(phi_j)
        velocity = (
            max_vel
            * global_velocity_scale
            * (1.0 - vel_margin)
            * proximity_scale
            * 0.7
            * abs(math.cos(phi_j))
        )
        effort = max_torque * (1.0 - torque_margin) * 0.4

        joint_states.append({
            "name": joint["name"],
            "position": position,
            "velocity": velocity,
            "effort": effort,
        })

    # End-effector positions from profile
    ee_positions = []
    for ee_def in profile.get("end_effectors", []):
        ws = profile.get("workspace", {})
        ws_min = ws.get("min", [-1.0, -1.0, 0.0])
        ws_max = ws.get("max", [1.0, 1.0, 1.5])
        center = [
            (ws_min[i] + ws_max[i]) / 2.0 for i in range(3)
        ]
        ee_positions.append({
            "name": ee_def.get("name", "end_effector"),
            "position": center,
        })
    if not ee_positions:
        ee_positions.append({
            "name": "end_effector",
            "position": [0.3, 0.0, 0.5],
        })

    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "source": "isaac_lab_campaign",
        "sequence": sequence,
        "joint_states": joint_states,
        "delta_time": delta_time,
        "end_effector_positions": ee_positions,
        "authority": {
            "pca_chain": "",
            "required_ops": ["actuate:*"],
        },
        "metadata": {
            "scenario": "A-07_dexterous_manipulation",
            "step": step_index,
            "total_steps": total_steps,
        },
    }


def run_dexterous_episode(
    profile: Dict[str, Any],
    steps: int = STEPS_PER_EPISODE,
    sequence_offset: int = 0,
) -> List[Dict[str, Any]]:
    """Run a full dexterous manipulation episode, returning all commands.

    This is the dry-run path: generates all commands without sending
    them to the Invariant bridge. Used for unit testing and offline
    validation.
    """
    commands = []
    for i in range(steps):
        cmd = generate_dexterous_command(
            profile=profile,
            step_index=i,
            total_steps=steps,
            sequence=sequence_offset + i + 1,
        )
        commands.append(cmd)
    return commands


def validate_command_within_limits(
    cmd: Dict[str, Any],
    profile: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """Check that a generated command stays within profile limits.

    Returns (all_ok, list_of_violations). This is a Python-side
    sanity check that mirrors the Rust validator's P1-P4 checks.
    """
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)

    violations = []
    joints_by_name = {j["name"]: j for j in profile["joints"]}

    for js in cmd["joint_states"]:
        name = js["name"]
        joint = joints_by_name.get(name)
        if joint is None:
            violations.append(f"Unknown joint: {name}")
            continue

        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin

        # P1: position limits
        pos = js["position"]
        if pos < eff_min - 1e-9 or pos > eff_max + 1e-9:
            violations.append(
                f"{name}: position {pos:.6f} outside "
                f"[{eff_min:.6f}, {eff_max:.6f}]"
            )

        # P2: velocity limits
        vel = js["velocity"]
        max_vel = joint["max_velocity"] * global_velocity_scale * (1.0 - vel_margin)
        if vel < -1e-9 or vel > max_vel + 1e-9:
            violations.append(
                f"{name}: velocity {vel:.6f} outside [0, {max_vel:.6f}]"
            )

        # P3: torque limits
        eff = js["effort"]
        max_eff = joint["max_torque"] * (1.0 - torque_margin)
        if eff < -1e-9 or eff > max_eff + 1e-9:
            violations.append(
                f"{name}: effort {eff:.6f} outside [0, {max_eff:.6f}]"
            )

    # P4: delta_time
    dt = cmd.get("delta_time", 0.0)
    if dt <= 0 or dt > max_delta_time + 1e-9:
        violations.append(
            f"delta_time {dt} outside (0, {max_delta_time}]"
        )

    return len(violations) == 0, violations
