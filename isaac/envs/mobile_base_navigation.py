"""Mobile-base navigation environment for the 15M campaign (Category C + F).

File: isaac/envs/mobile_base_navigation.py
Spec: C-* workspace happy-path + F-* environmental no-op, for wheeled
mobile platforms (Stretch, TIAGo).

The generator emits a slow rectangular sweep through the base footprint
inside the workspace AABB, with the on-board manipulator parked at its
joint midpoints. Every command should PASS: positions/velocities/torques
stay inside the profile envelope, the EE stays inside the workspace,
locomotion velocity stays well below `max_locomotion_velocity`, and
heading rate stays well below `max_heading_rate`.

Profile subset: hello_stretch, pal_tiago.

Invariants exercised (pass path): P1, P2, P3, P5 (EE in workspace),
P19/P20 (locomotion envelope); A1, A2, A3.
"""

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROFILES_DIR = _REPO_ROOT / "profiles" / "robotics"

MOBILE_PROFILES = ["hello_stretch", "pal_tiago"]
STEPS_PER_EPISODE = 300
EPISODES_TOTAL = 200_000
EPISODES_PER_PROFILE = EPISODES_TOTAL // len(MOBILE_PROFILES)

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


def _workspace_centre(profile: Dict[str, Any]) -> Tuple[float, float, float]:
    ws = profile.get("workspace", {})
    ws_min = ws.get("min", [-1.0, -1.0, 0.0])
    ws_max = ws.get("max", [1.0, 1.0, 1.0])
    return tuple((ws_min[i] + ws_max[i]) / 2.0 for i in range(3))  # type: ignore[return-value]


def _workspace_inset_extent(profile: Dict[str, Any], inset: float = 0.20) -> Tuple[float, float]:
    """Return half-extents (rx, ry) of the workspace AABB shrunk by `inset`
    on every side, used to size the base sweep so the EE stays well inside
    the workspace under P5."""
    ws = profile.get("workspace", {})
    ws_min = ws.get("min", [-1.0, -1.0, 0.0])
    ws_max = ws.get("max", [1.0, 1.0, 1.0])
    half_x = max(0.0, (ws_max[0] - ws_min[0]) / 2.0 - inset)
    half_y = max(0.0, (ws_max[1] - ws_min[1]) / 2.0 - inset)
    # Cap the sweep at 0.4 m so even tight workspaces produce a reasonable
    # base motion without crowding the AABB.
    return (min(half_x, 0.4), min(half_y, 0.4))


def generate_mobile_base_command(
    profile: Dict[str, Any],
    step_index: int,
    total_steps: int,
    sequence: int,
) -> Dict[str, Any]:
    """Emit a slow lemniscate sweep of the base + parked arm."""
    margins = get_margins(profile)
    pos_margin = margins["position_margin"]
    vel_margin = margins["velocity_margin"]
    torque_margin = margins["torque_margin"]

    global_velocity_scale = profile.get("global_velocity_scale", 1.0)
    max_delta_time = profile.get("max_delta_time", 0.01)
    delta_time = 0.5 * max_delta_time

    # Park every joint at its effective midpoint.
    joints = profile["joints"]
    joint_states: List[Dict[str, Any]] = []
    for joint in joints:
        j_min = joint["min"]
        j_max = joint["max"]
        j_range = j_max - j_min
        eff_min = j_min + j_range * pos_margin
        eff_max = j_max - j_range * pos_margin
        mid = (eff_min + eff_max) / 2.0
        joint_states.append({
            "name": joint["name"],
            "position": mid,
            "velocity": 0.0,
            "effort": joint["max_torque"] * (1.0 - torque_margin) * 0.05,
        })

    loco = profile.get("locomotion", {})
    max_v = loco.get("max_locomotion_velocity", 1.0)
    max_heading_rate = loco.get("max_heading_rate", 1.5)

    # Lemniscate of Bernoulli: x = a cos t / (1 + sin^2 t),
    #                          y = a sin t cos t / (1 + sin^2 t).
    centre = _workspace_centre(profile)
    rx, ry = _workspace_inset_extent(profile)
    t = (step_index / max(total_steps, 1)) * 2.0 * math.pi
    denom = 1.0 + math.sin(t) ** 2
    base_x = centre[0] + rx * math.cos(t) / denom
    base_y = centre[1] + ry * math.sin(t) * math.cos(t) / denom
    # Tangent angular velocity stays well below `max_heading_rate`.
    heading_rate = 0.20 * max_heading_rate * math.cos(t)
    # Linear velocity at 30% of `max_locomotion_velocity`, derived from
    # the lemniscate derivative magnitude (bounded; never exceeds rx + ry).
    base_speed = 0.30 * max_v

    locomotion_state = {
        "base_linear_velocity": [base_speed * math.cos(t), base_speed * math.sin(t), 0.0],
        "base_angular_velocity": [0.0, 0.0, heading_rate],
        "step_length": 0.0,
        "step_height": 0.0,
        "swing_foot": "",
        "stance_phase": 0.0,
        "imu_pitch_rad": 0.0,
        "imu_roll_rad": 0.0,
    }

    # End-effector at workspace centre — guaranteed P5 PASS.
    ee_positions = []
    ws_centre = list(centre)
    for ee_def in profile.get("end_effectors", []):
        ee_positions.append({
            "name": ee_def.get("name", "end_effector"),
            "position": ws_centre,
        })
    if not ee_positions:
        ee_positions.append({"name": "end_effector", "position": ws_centre})

    now = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "source": "isaac_lab_campaign",
        "sequence": sequence,
        "joint_states": joint_states,
        "delta_time": delta_time,
        "end_effector_positions": ee_positions,
        "center_of_mass": None,
        "locomotion_state": locomotion_state,
        "authority": {
            "pca_chain": "",
            "required_ops": ["actuate:*"],
        },
        "metadata": {
            "scenario": "C-01_workspace_boundary_sweep",
            "step": str(step_index),
            "total_steps": str(total_steps),
            "base_x": f"{base_x:.6f}",
            "base_y": f"{base_y:.6f}",
        },
    }


def run_mobile_base_episode(
    profile: Dict[str, Any],
    steps: int = STEPS_PER_EPISODE,
    sequence_offset: int = 0,
) -> List[Dict[str, Any]]:
    return [
        generate_mobile_base_command(
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
    """Python-side P1–P3 + P5 + locomotion sanity check."""
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
            violations.append(f"{name}: position {pos:.6f} outside [{eff_min:.6f}, {eff_max:.6f}]")
        vel = js["velocity"]
        max_vel = joint["max_velocity"] * global_velocity_scale * (1.0 - vel_margin)
        if vel < -1e-9 or vel > max_vel + 1e-9:
            violations.append(f"{name}: velocity {vel:.6f} outside [0, {max_vel:.6f}]")
        eff = js["effort"]
        max_eff = joint["max_torque"] * (1.0 - torque_margin)
        if eff < -1e-9 or eff > max_eff + 1e-9:
            violations.append(f"{name}: effort {eff:.6f} outside [0, {max_eff:.6f}]")

    dt = cmd.get("delta_time", 0.0)
    if dt <= 0 or dt > max_delta_time + 1e-9:
        violations.append(f"delta_time {dt} outside (0, {max_delta_time}]")

    # P5: EE inside workspace AABB.
    ws = profile.get("workspace", {})
    ws_min = ws.get("min")
    ws_max = ws.get("max")
    if ws_min is not None and ws_max is not None:
        for ee in cmd.get("end_effector_positions", []):
            p = ee["position"]
            if not all(ws_min[i] - 1e-9 <= p[i] <= ws_max[i] + 1e-9 for i in range(3)):
                violations.append(f"EE {ee['name']} outside workspace AABB at {p}")

    loco = profile.get("locomotion")
    ls = cmd.get("locomotion_state")
    if loco is not None and ls is not None:
        max_v = loco.get("max_locomotion_velocity", 1.0)
        max_heading_rate = loco.get("max_heading_rate", 1.5)
        vx, vy, _ = ls.get("base_linear_velocity", [0, 0, 0])
        if math.hypot(vx, vy) > max_v + 1e-9:
            violations.append(f"base speed {math.hypot(vx, vy):.6f} > max {max_v}")
        wz = ls.get("base_angular_velocity", [0, 0, 0])[2]
        if abs(wz) > max_heading_rate + 1e-9:
            violations.append(f"heading rate {wz} > max {max_heading_rate}")

    return len(violations) == 0, violations
