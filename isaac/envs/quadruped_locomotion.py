"""Quadruped locomotion environment for the 15M campaign (Category D).

File: isaac/envs/quadruped_locomotion.py
Spec: D-02 walking gait validation + D-05 push recovery / fall (happy
side) for quadrupedal platforms. Mirrors `humanoid_walk.py` for
quadrupeds — Spot, ANYmal, generic 12-DOF — using a trot gait that
alternates diagonal foot pairs by step parity.

The generator emits a legitimate trot at 40% of the profile's
locomotion envelope so every command should PASS under P9 (stability),
P19 (step length), P20 (heading), and P21 (incline). Diagonal foot
pair alternates by step parity; swing height stays inside
(`min_foot_clearance`, `max_step_height`).

Profile subset: spot, spot_with_arm, anybotics_anymal, quadruped_12dof.

Invariants exercised (pass path): P1, P2, P3, P9, P19, P20, P21;
A1, A2, A3.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROFILES_DIR = _REPO_ROOT / "profiles" / "robotics"

QUADRUPED_PROFILES = [
    "spot",
    "spot_with_arm",
    "anybotics_anymal",
]
STEPS_PER_EPISODE = 300
EPISODES_TOTAL = 300_000
EPISODES_PER_PROFILE = EPISODES_TOTAL // len(QUADRUPED_PROFILES)

DEFAULT_MARGINS = {
    "position_margin": 0.05,
    "velocity_margin": 0.10,
    "torque_margin": 0.10,
}

# A trot alternates the FL-RR pair with the FR-RL pair.
TROT_PAIRS = ("FL_RR", "FR_RL")


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


def _support_polygon_centroid(profile: Dict[str, Any]) -> Tuple[float, float, float]:
    stab = profile.get("stability", {})
    poly = stab.get("support_polygon")
    if not poly:
        return (0.0, 0.0, 0.6)
    xs = [p[0] for p in poly]
    ys = [p[1] for p in poly]
    cx = sum(xs) / len(xs)
    cy = sum(ys) / len(ys)
    ws = profile.get("workspace", {})
    ws_max = ws.get("max", [0.0, 0.0, 0.8])
    return (cx, cy, ws_max[2] * 0.5)


def generate_quadruped_command(
    profile: Dict[str, Any],
    step_index: int,
    total_steps: int,
    sequence: int,
) -> Dict[str, Any]:
    """Emit a single quadruped trot command in the happy band."""
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)
    delta_time = 0.5 * max_delta_time

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
        # 12% sway with per-joint phase — trot cycles many joints in lock-step.
        position = mid + 0.12 * half * math.sin(phi + j * 0.2)
        velocity = (
            joint["max_velocity"]
            * global_velocity_scale
            * (1.0 - vel_margin)
            * 0.12
            * abs(math.cos(phi + j * 0.2))
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
    max_step = loco.get("max_step_length", 0.3)
    max_step_height = loco.get("max_step_height", 0.15)
    min_foot_clearance = loco.get("min_foot_clearance", 0.02)
    max_heading_rate = loco.get("max_heading_rate", 1.2)

    swing_pair = TROT_PAIRS[step_index % 2]
    swing_height = max(min_foot_clearance + 0.005, max_step_height * 0.5)

    # Quadrupeds typically don't expose a single `swing_foot`; we encode the
    # diagonal trot pair via metadata and leave swing_foot empty.
    locomotion_state = {
        "base_linear_velocity": [0.40 * max_v, 0.0, 0.0],
        "base_angular_velocity": [0.0, 0.0, 0.15 * max_heading_rate],
        "step_length": 0.50 * max_step,
        "step_height": swing_height,
        "swing_foot": "",
        "stance_phase": (step_index / max(total_steps, 1)) % 1.0,
        "imu_pitch_rad": 0.0,
        "imu_roll_rad": 0.0,
    }

    com = list(_support_polygon_centroid(profile))

    # Optional end-effectors (Spot-with-arm); idle at workspace centre.
    ee_positions = []
    ws = profile.get("workspace", {})
    ws_min = ws.get("min", [-0.5, -0.5, 0.0])
    ws_max = ws.get("max", [0.5, 0.5, 1.0])
    centre = [(ws_min[i] + ws_max[i]) / 2.0 for i in range(3)]
    for ee_def in profile.get("end_effectors", []):
        ee_positions.append({
            "name": ee_def.get("name", "end_effector"),
            "position": centre,
        })

    now = datetime.now(timezone.utc).isoformat()
    cmd: Dict[str, Any] = {
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
            "trot_pair": swing_pair,
        },
    }
    return cmd


def run_quadruped_episode(
    profile: Dict[str, Any],
    steps: int = STEPS_PER_EPISODE,
    sequence_offset: int = 0,
) -> List[Dict[str, Any]]:
    return [
        generate_quadruped_command(
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

    loco = profile.get("locomotion")
    ls = cmd.get("locomotion_state")
    if loco is not None and ls is not None:
        max_v = loco.get("max_locomotion_velocity", 1.0)
        max_step = loco.get("max_step_length", 0.3)
        max_step_height = loco.get("max_step_height", 0.15)
        min_foot_clearance = loco.get("min_foot_clearance", 0.0)
        max_heading_rate = loco.get("max_heading_rate", 1.2)
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
