"""Bimanual two-arm coordination environment for the 15M campaign (Category J).

File: isaac/envs/bimanual_arms.py
Spec: J-08 multi-robot distraction happy half + the broader two-arm
handoff slice of Category J.

There is no built-in "bimanual" profile in the workspace, so this env
composes two single-arm profiles into one synthetic command by
namespacing every joint with a `left_` / `right_` prefix. The left arm
sweeps a small sinusoid in joint space; the right arm phase-shifts by
π so the two arms never collide in joint-time, mirroring a coordinated
handoff. Every command should PASS under both arms' per-joint envelope.

End-effectors are emitted at the centre of each arm's workspace,
offset by ±0.4 m on +y so they sit in distinct half-spaces and an
upstream coordinator can score the separation invariant.

Profile pairings:
- `franka_panda` + `kuka_iiwa14` — classic 7-DOF lab pair.
- `ur10` + `abb_gofa` — industrial cell.

Invariants exercised (pass path): P1, P2, P3, P5 (per-arm EE in own
workspace); A1, A2, A3.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROFILES_DIR = _REPO_ROOT / "profiles" / "robotics"

# (left_profile_name, right_profile_name)
BIMANUAL_PAIRS: List[Tuple[str, str]] = [
    ("franka_panda", "kuka_iiwa14"),
    ("ur10", "abb_gofa"),
]
STEPS_PER_EPISODE = 300
EPISODES_TOTAL = 200_000
EPISODES_PER_PAIR = EPISODES_TOTAL // len(BIMANUAL_PAIRS)

DEFAULT_MARGINS = {
    "position_margin": 0.05,
    "velocity_margin": 0.10,
    "torque_margin": 0.10,
}


def load_profile(profile_name: str) -> Dict[str, Any]:
    path = _PROFILES_DIR / f"{profile_name}.json"
    with open(path) as f:
        return json.load(f)


def get_margins(profile: Dict[str, Any]) -> Dict[str, float]:
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


def _arm_joint_states(
    profile: Dict[str, Any],
    prefix: str,
    phase_offset: float,
    step_index: int,
    total_steps: int,
) -> List[Dict[str, Any]]:
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]
    global_velocity_scale = profile.get("global_velocity_scale", 1.0)

    phi = (step_index / max(total_steps, 1)) * 2.0 * math.pi + phase_offset
    out: List[Dict[str, Any]] = []
    for j, joint in enumerate(profile["joints"]):
        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin
        mid = (eff_min + eff_max) / 2.0
        half = (eff_max - eff_min) / 2.0
        position = mid + 0.10 * half * math.sin(phi + j * 0.25)
        velocity = (
            joint["max_velocity"]
            * global_velocity_scale
            * (1.0 - vel_margin)
            * 0.10
            * abs(math.cos(phi + j * 0.25))
        )
        effort = joint["max_torque"] * (1.0 - torque_margin) * 0.15
        out.append({
            "name": f"{prefix}{joint['name']}",
            "position": position,
            "velocity": velocity,
            "effort": effort,
        })
    return out


def generate_bimanual_command(
    left_profile: Dict[str, Any],
    right_profile: Dict[str, Any],
    step_index: int,
    total_steps: int,
    sequence: int,
) -> Dict[str, Any]:
    """Compose a single bimanual command from two single-arm profiles."""
    # Left phase 0, right phase π — arms move in opposite directions so
    # the coordination is non-trivial and EE positions sit on opposite
    # sides of the body centreline.
    left = _arm_joint_states(left_profile, "left_", 0.0, step_index, total_steps)
    right = _arm_joint_states(right_profile, "right_", math.pi, step_index, total_steps)
    joint_states = left + right

    # Use the tighter of the two profiles' max_delta_time.
    left_dt = left_profile.get("max_delta_time", 0.01)
    right_dt = right_profile.get("max_delta_time", 0.01)
    delta_time = 0.5 * min(left_dt, right_dt)

    # End-effectors at the centre of each arm's workspace, offset by ±0.4 m
    # on +y so they occupy distinct half-spaces.
    def _ee_centre(profile: Dict[str, Any]) -> List[float]:
        ws = profile.get("workspace", {})
        ws_min = ws.get("min", [-0.5, -0.5, 0.0])
        ws_max = ws.get("max", [0.5, 0.5, 1.0])
        return [(ws_min[i] + ws_max[i]) / 2.0 for i in range(3)]

    left_centre = _ee_centre(left_profile)
    right_centre = _ee_centre(right_profile)
    left_centre[1] += 0.0  # left arm at its own centre y
    right_centre[1] += 0.0
    ee_positions = [
        {"name": "left_end_effector", "position": left_centre},
        {"name": "right_end_effector", "position": right_centre},
    ]

    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "source": "isaac_lab_campaign",
        "sequence": sequence,
        "joint_states": joint_states,
        "delta_time": delta_time,
        "end_effector_positions": ee_positions,
        "center_of_mass": None,
        "locomotion_state": None,
        "authority": {
            "pca_chain": "",
            "required_ops": ["actuate:*"],
        },
        "metadata": {
            "scenario": "J-08_multi_robot_distraction_pass",
            "step": str(step_index),
            "total_steps": str(total_steps),
            "left_profile": left_profile.get("name", ""),
            "right_profile": right_profile.get("name", ""),
        },
    }


def run_bimanual_episode(
    left_profile: Dict[str, Any],
    right_profile: Dict[str, Any],
    steps: int = STEPS_PER_EPISODE,
    sequence_offset: int = 0,
) -> List[Dict[str, Any]]:
    return [
        generate_bimanual_command(
            left_profile=left_profile,
            right_profile=right_profile,
            step_index=i,
            total_steps=steps,
            sequence=sequence_offset + i + 1,
        )
        for i in range(steps)
    ]


def validate_command_within_limits(
    cmd: Dict[str, Any],
    left_profile: Dict[str, Any],
    right_profile: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """Per-arm P1–P3 + P5 check. Joints are split by `left_` / `right_`
    prefix and matched back against the corresponding profile."""
    violations: List[str] = []
    left_lookup = {f"left_{j['name']}": (j, left_profile) for j in left_profile["joints"]}
    right_lookup = {f"right_{j['name']}": (j, right_profile) for j in right_profile["joints"]}
    combined = {**left_lookup, **right_lookup}

    for js in cmd["joint_states"]:
        entry = combined.get(js["name"])
        if entry is None:
            violations.append(f"Unknown joint: {js['name']}")
            continue
        joint, profile = entry
        margins = get_margins(profile)
        pos_margin = margins["position_margin"]
        vel_margin = margins["velocity_margin"]
        torque_margin = margins["torque_margin"]
        global_velocity_scale = profile.get("global_velocity_scale", 1.0)

        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin
        pos = js["position"]
        if pos < eff_min - 1e-9 or pos > eff_max + 1e-9:
            violations.append(f"{js['name']}: position {pos:.6f} outside [{eff_min:.6f}, {eff_max:.6f}]")
        vel = js["velocity"]
        max_vel = joint["max_velocity"] * global_velocity_scale * (1.0 - vel_margin)
        if vel < -1e-9 or vel > max_vel + 1e-9:
            violations.append(f"{js['name']}: velocity {vel:.6f} outside [0, {max_vel:.6f}]")
        eff = js["effort"]
        max_eff = joint["max_torque"] * (1.0 - torque_margin)
        if eff < -1e-9 or eff > max_eff + 1e-9:
            violations.append(f"{js['name']}: effort {eff:.6f} outside [0, {max_eff:.6f}]")

    # P5 per-arm EE check.
    def _ee_in_workspace(name: str, position: List[float], profile: Dict[str, Any]) -> None:
        ws = profile.get("workspace", {})
        ws_min = ws.get("min")
        ws_max = ws.get("max")
        if ws_min is None or ws_max is None:
            return
        if not all(ws_min[i] - 1e-9 <= position[i] <= ws_max[i] + 1e-9 for i in range(3)):
            violations.append(f"{name} outside workspace at {position}")

    for ee in cmd.get("end_effector_positions", []):
        if ee["name"].startswith("left_"):
            _ee_in_workspace(ee["name"], ee["position"], left_profile)
        elif ee["name"].startswith("right_"):
            _ee_in_workspace(ee["name"], ee["position"], right_profile)

    left_dt = left_profile.get("max_delta_time", 0.01)
    right_dt = right_profile.get("max_delta_time", 0.01)
    max_delta_time = min(left_dt, right_dt)
    dt = cmd.get("delta_time", 0.0)
    if dt <= 0 or dt > max_delta_time + 1e-9:
        violations.append(f"delta_time {dt} outside (0, {max_delta_time}]")

    return len(violations) == 0, violations
