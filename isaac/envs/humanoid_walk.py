"""Humanoid bipedal walking environment for the 15M campaign (Category D).

File: isaac/envs/humanoid_walk.py
Spec: D-02 walking gait validation + D-01 COM stability + the broader
locomotion happy-path slice of Category D.

This module mirrors the structure of `dexterous_manipulation.py`:
profile + step index in → one valid `Command` JSON dict out. No Isaac
Lab dependency at import time, so it can be unit-tested directly.

The generator emits a legitimate sinusoidal walking gait at 50% of the
profile's locomotion envelope (velocity / heading rate / step length) so
every command should PASS under P9 (stability), P19 (step length), P20
(heading), and P21 (incline). Swing foot alternates left/right by step
parity and rises to 60% of `max_step_height`.

Profile subset: humanoid_28dof, unitree_h1, bd_atlas (every built-in
profile with a `locomotion` block + a `stability.support_polygon`).

Invariants exercised (pass path): P1, P2, P3, P9, P19, P20, P21;
A1, A2, A3.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROFILES_DIR = _REPO_ROOT / "profiles" / "robotics"

HUMANOID_PROFILES = ["unitree_h1", "bd_atlas"]
STEPS_PER_EPISODE = 300
EPISODES_TOTAL = 300_000
EPISODES_PER_PROFILE = EPISODES_TOTAL // len(HUMANOID_PROFILES)

DEFAULT_MARGINS = {
    "position_margin": 0.05,
    "velocity_margin": 0.10,
    "torque_margin": 0.10,
}


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Load a profile JSON from `profiles/robotics/<name>.json`."""
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


def _support_polygon_centroid(profile: Dict[str, Any]) -> Tuple[float, float, float]:
    """Return the (x, y, z) centroid of the support polygon, falling back to the
    origin when the profile has no stability config."""
    stab = profile.get("stability", {})
    poly = stab.get("support_polygon")
    if not poly:
        return (0.0, 0.0, 1.0)
    xs = [p[0] for p in poly]
    ys = [p[1] for p in poly]
    cx = sum(xs) / len(xs)
    cy = sum(ys) / len(ys)
    # Default COM height: middle of the profile's workspace if available.
    ws = profile.get("workspace", {})
    ws_max = ws.get("max", [0.0, 0.0, 2.0])
    return (cx, cy, ws_max[2] * 0.5)


def generate_humanoid_walk_command(
    profile: Dict[str, Any],
    step_index: int,
    total_steps: int,
    sequence: int,
) -> Dict[str, Any]:
    """Generate a single humanoid walking command per the D-02 spec.

    Joint state stays near the midpoint (small sinusoidal sway) while the
    locomotion fields exercise a legitimate gait at 50% of every profile
    envelope, with swing foot alternating left/right by step parity.
    """
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)
    delta_time = 0.5 * max_delta_time

    # Per-joint small sinusoidal sway in the safe band.
    joints = profile["joints"]
    joint_states: List[Dict[str, Any]] = []
    phi = (step_index / max(total_steps, 1)) * 2.0 * math.pi
    for j, joint in enumerate(joints):
        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin
        mid = (eff_min + eff_max) / 2.0
        half = (eff_max - eff_min) / 2.0
        # 10% sway, distinct phase per joint so coordination isn't trivial.
        position = mid + 0.10 * half * math.sin(phi + j * 0.3)
        velocity = (
            joint["max_velocity"]
            * global_velocity_scale
            * (1.0 - vel_margin)
            * 0.10
            * abs(math.cos(phi + j * 0.3))
        )
        effort = joint["max_torque"] * (1.0 - torque_margin) * 0.20
        joint_states.append({
            "name": joint["name"],
            "position": position,
            "velocity": velocity,
            "effort": effort,
        })

    loco = profile.get("locomotion", {})
    max_v = loco.get("max_locomotion_velocity", 1.0)
    max_step = loco.get("max_step_length", 0.5)
    max_step_height = loco.get("max_step_height", 0.20)
    min_foot_clearance = loco.get("min_foot_clearance", 0.02)
    max_heading_rate = loco.get("max_heading_rate", 1.5)

    swing_foot = "left" if (step_index % 2 == 0) else "right"
    # Swing height stays inside (min_foot_clearance, max_step_height)
    # — pick 60% of max_step_height, clamped above min_foot_clearance.
    swing_height = max(min_foot_clearance + 0.005, max_step_height * 0.6)

    locomotion_state = {
        "base_linear_velocity": [0.50 * max_v, 0.0, 0.0],
        "base_angular_velocity": [0.0, 0.0, 0.25 * max_heading_rate],
        "step_length": 0.60 * max_step,
        "step_height": swing_height,
        "swing_foot": swing_foot,
        "stance_phase": (step_index / max(total_steps, 1)) % 1.0,
        "imu_pitch_rad": 0.0,
        "imu_roll_rad": 0.0,
    }

    # COM at the support polygon centroid — guaranteed P9 PASS.
    com = list(_support_polygon_centroid(profile))

    # End-effectors (hands) from the profile, parked at the workspace centre.
    ee_positions = []
    ws = profile.get("workspace", {})
    ws_min = ws.get("min", [-0.5, -0.5, 0.5])
    ws_max = ws.get("max", [0.5, 0.5, 1.5])
    centre = [(ws_min[i] + ws_max[i]) / 2.0 for i in range(3)]
    for ee_def in profile.get("end_effectors", []):
        ee_positions.append({
            "name": ee_def.get("name", "end_effector"),
            "position": centre,
        })
    if not ee_positions:
        ee_positions.append({"name": "end_effector", "position": centre})

    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "source": "isaac_lab_campaign",
        "sequence": sequence,
        "joint_states": joint_states,
        "delta_time": delta_time,
        "end_effector_positions": ee_positions,
        "center_of_mass": com,
        "locomotion_state": locomotion_state,
        "authority": {
            "pca_chain": "",
            "required_ops": ["actuate:*"],
        },
        "metadata": {
            "scenario": "D-02_walking_gait_validation",
            "step": str(step_index),
            "total_steps": str(total_steps),
            "swing_foot": swing_foot,
        },
    }


def run_humanoid_walk_episode(
    profile: Dict[str, Any],
    steps: int = STEPS_PER_EPISODE,
    sequence_offset: int = 0,
) -> List[Dict[str, Any]]:
    """Run a full humanoid walking episode, returning every command.

    Dry-run path: emits commands without going through the Invariant bridge.
    """
    return [
        generate_humanoid_walk_command(
            profile=profile,
            step_index=i,
            total_steps=steps,
            sequence=sequence_offset + i + 1,
        )
        for i in range(steps)
    ]


def validate_command_within_limits(
    cmd: Dict[str, Any],
    profile: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """Python-side sanity check mirroring the Rust validator's P1–P3 +
    locomotion checks. Returns (all_ok, violations)."""
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)

    violations: List[str] = []
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
        pos = js["position"]
        if pos < eff_min - 1e-9 or pos > eff_max + 1e-9:
            violations.append(
                f"{name}: position {pos:.6f} outside "
                f"[{eff_min:.6f}, {eff_max:.6f}]"
            )
        vel = js["velocity"]
        max_vel = joint["max_velocity"] * global_velocity_scale * (1.0 - vel_margin)
        if vel < -1e-9 or vel > max_vel + 1e-9:
            violations.append(
                f"{name}: velocity {vel:.6f} outside [0, {max_vel:.6f}]"
            )
        eff = js["effort"]
        max_eff = joint["max_torque"] * (1.0 - torque_margin)
        if eff < -1e-9 or eff > max_eff + 1e-9:
            violations.append(
                f"{name}: effort {eff:.6f} outside [0, {max_eff:.6f}]"
            )

    dt = cmd.get("delta_time", 0.0)
    if dt <= 0 or dt > max_delta_time + 1e-9:
        violations.append(f"delta_time {dt} outside (0, {max_delta_time}]")

    # Locomotion envelope checks
    loco = profile.get("locomotion")
    ls = cmd.get("locomotion_state")
    if loco is not None and ls is not None:
        max_v = loco.get("max_locomotion_velocity", 1.0)
        max_step = loco.get("max_step_length", 0.5)
        max_step_height = loco.get("max_step_height", 0.20)
        min_foot_clearance = loco.get("min_foot_clearance", 0.0)
        max_heading_rate = loco.get("max_heading_rate", 1.5)
        vx = ls.get("base_linear_velocity", [0, 0, 0])[0]
        if abs(vx) > max_v + 1e-9:
            violations.append(f"base velocity {vx} > max {max_v}")
        if ls.get("step_length", 0.0) > max_step + 1e-9:
            violations.append("step_length exceeds max_step_length")
        sh = ls.get("step_height", 0.0)
        if sh > max_step_height + 1e-9 or sh < min_foot_clearance - 1e-9:
            violations.append("step_height outside [min_foot_clearance, max]")
        wz = ls.get("base_angular_velocity", [0, 0, 0])[2]
        if abs(wz) > max_heading_rate + 1e-9:
            violations.append(f"heading rate {wz} > max {max_heading_rate}")

    return len(violations) == 0, violations
