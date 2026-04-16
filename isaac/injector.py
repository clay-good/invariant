"""Adversarial command injector for Isaac Lab campaigns.

Mirrors the Rust injector (crates/invariant-sim/src/injector.rs) so that
the Python campaign runner can mutate physics-generated commands to create
adversarial scenarios. Each injection type corrupts a specific field to
trigger a known safety check.

Usage:
    from injector import inject, InjectionType

    cmd = build_invariant_command(...)   # from real Isaac Lab state
    inject(cmd, InjectionType.VELOCITY_OVERSHOOT)  # mutate in-place
    verdict = bridge.validate(cmd)
    assert not verdict["approved"]       # validator must catch it
"""

import math
import random
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class InjectionType(Enum):
    """Adversarial injection types matching the Rust injector."""

    # Physics violations
    VELOCITY_OVERSHOOT = auto()
    POSITION_VIOLATION = auto()
    TORQUE_SPIKE = auto()
    WORKSPACE_ESCAPE = auto()
    DELTA_TIME_VIOLATION = auto()
    SELF_COLLISION = auto()
    STABILITY_VIOLATION = auto()

    # Authority / crypto
    AUTHORITY_STRIP = auto()
    REPLAY_ATTACK = auto()
    NAN_INJECTION = auto()

    # Locomotion
    LOCOMOTION_OVERSPEED = auto()
    SLIP_VIOLATION = auto()
    FOOT_CLEARANCE_VIOLATION = auto()
    STOMP_VIOLATION = auto()
    STEP_OVEREXTENSION = auto()
    HEADING_SPINOUT = auto()
    GROUND_REACTION_SPIKE = auto()

    # Environmental
    TERRAIN_INCLINE = auto()
    TEMPERATURE_SPIKE = auto()
    BATTERY_DRAIN = auto()
    LATENCY_SPIKE = auto()
    E_STOP_ENGAGE = auto()

    # Manipulation
    PROXIMITY_OVERSPEED = auto()
    FORCE_OVERLOAD = auto()
    GRASP_FORCE_VIOLATION = auto()
    PAYLOAD_OVERLOAD = auto()
    FORCE_RATE_SPIKE = auto()


def inject(cmd: Dict[str, Any], injection: InjectionType) -> None:
    """Mutate a command dict in-place to inject an adversarial fault.

    The command should be a valid Invariant Command JSON dict (as produced
    by build_invariant_command or extracted from Isaac Lab observations).
    After injection, the command should be REJECTED by the validator.
    """
    _INJECTORS[injection](cmd)


# ---------------------------------------------------------------------------
# Individual injectors
# ---------------------------------------------------------------------------


def _inject_velocity_overshoot(cmd: Dict[str, Any]) -> None:
    """Set first joint velocity to 10x a typical limit."""
    if cmd.get("joint_states"):
        cmd["joint_states"][0]["velocity"] = 50.0


def _inject_position_violation(cmd: Dict[str, Any]) -> None:
    """Set first joint position way beyond any profile limit."""
    if cmd.get("joint_states"):
        cmd["joint_states"][0]["position"] = 999.0


def _inject_torque_spike(cmd: Dict[str, Any]) -> None:
    """Set first joint effort to 10x a typical limit."""
    if cmd.get("joint_states"):
        cmd["joint_states"][0]["effort"] = 5000.0


def _inject_workspace_escape(cmd: Dict[str, Any]) -> None:
    """Move end-effector far outside any workspace."""
    if cmd.get("end_effector_positions"):
        cmd["end_effector_positions"][0]["position"] = [100.0, 100.0, 100.0]
    else:
        cmd["end_effector_positions"] = [
            {"name": "ee", "position": [100.0, 100.0, 100.0]}
        ]


def _inject_delta_time_violation(cmd: Dict[str, Any]) -> None:
    """Set delta_time to negative (impossible)."""
    cmd["delta_time"] = -1.0


def _inject_self_collision(cmd: Dict[str, Any]) -> None:
    """Move collision-pair links to the same position."""
    if cmd.get("end_effector_positions") and len(cmd["end_effector_positions"]) >= 2:
        cmd["end_effector_positions"][1]["position"] = list(
            cmd["end_effector_positions"][0]["position"]
        )


def _inject_stability_violation(cmd: Dict[str, Any]) -> None:
    """Move CoM far outside any support polygon."""
    cmd["center_of_mass"] = [50.0, 50.0, 0.0]


def _inject_authority_strip(cmd: Dict[str, Any]) -> None:
    """Remove the PCA chain entirely."""
    cmd["authority"] = {"pca_chain": "", "required_ops": ["actuate:*"]}


def _inject_replay_attack(cmd: Dict[str, Any]) -> None:
    """Set sequence to 0 (always behind any running validator)."""
    cmd["sequence"] = 0


def _inject_nan(cmd: Dict[str, Any]) -> None:
    """Inject NaN into joint positions."""
    if cmd.get("joint_states"):
        cmd["joint_states"][0]["position"] = float("nan")
        cmd["joint_states"][0]["velocity"] = float("nan")


def _inject_locomotion_overspeed(cmd: Dict[str, Any]) -> None:
    """Set base velocity far above limit."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["base_velocity"] = [50.0, 0.0, 0.0]


def _inject_slip_violation(cmd: Dict[str, Any]) -> None:
    """Inject friction cone violation on a foot."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["feet"] = [
        {
            "name": "foot_0",
            "in_contact": True,
            "ground_reaction_force": [500.0, 500.0, 10.0],
            "height": 0.0,
        }
    ]


def _inject_foot_clearance(cmd: Dict[str, Any]) -> None:
    """Swing foot below ground."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["feet"] = [
        {
            "name": "foot_0",
            "in_contact": False,
            "ground_reaction_force": [0.0, 0.0, 0.0],
            "height": -0.5,
        }
    ]


def _inject_stomp(cmd: Dict[str, Any]) -> None:
    """Foot height 3x max step height."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["feet"] = [
        {
            "name": "foot_0",
            "in_contact": False,
            "ground_reaction_force": [0.0, 0.0, 0.0],
            "height": 3.0,
        }
    ]


def _inject_step_overextension(cmd: Dict[str, Any]) -> None:
    """Step length 3x max."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["step_length"] = 10.0


def _inject_heading_spinout(cmd: Dict[str, Any]) -> None:
    """Heading rate 5x max."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["heading_rate"] = 50.0


def _inject_ground_reaction_spike(cmd: Dict[str, Any]) -> None:
    """GRF spike far beyond limit."""
    cmd["locomotion_state"] = cmd.get("locomotion_state") or {
        "base_velocity": [0.0, 0.0, 0.0],
        "heading_rate": 0.0,
        "feet": [],
        "step_length": 0.0,
    }
    cmd["locomotion_state"]["feet"] = [
        {
            "name": "foot_0",
            "in_contact": True,
            "ground_reaction_force": [0.0, 0.0, 50000.0],
            "height": 0.0,
        }
    ]


def _inject_terrain_incline(cmd: Dict[str, Any]) -> None:
    """Set IMU pitch/roll to extreme terrain angle."""
    cmd["environment_state"] = cmd.get("environment_state") or {}
    cmd["environment_state"]["imu_pitch_rad"] = 1.0  # ~57 degrees
    cmd["environment_state"]["imu_roll_rad"] = 0.8


def _inject_temperature_spike(cmd: Dict[str, Any]) -> None:
    """Set actuator temperatures way above limit."""
    cmd["environment_state"] = cmd.get("environment_state") or {}
    cmd["environment_state"]["actuator_temperatures"] = [
        {"joint_name": "joint_0", "temperature_celsius": 200.0}
    ]


def _inject_battery_drain(cmd: Dict[str, Any]) -> None:
    """Set battery to critically low."""
    cmd["environment_state"] = cmd.get("environment_state") or {}
    cmd["environment_state"]["battery_percentage"] = 1.0


def _inject_latency_spike(cmd: Dict[str, Any]) -> None:
    """Set communication latency way above limit."""
    cmd["environment_state"] = cmd.get("environment_state") or {}
    cmd["environment_state"]["communication_latency_ms"] = 5000.0


def _inject_e_stop(cmd: Dict[str, Any]) -> None:
    """Engage the emergency stop."""
    cmd["environment_state"] = cmd.get("environment_state") or {}
    cmd["environment_state"]["e_stop_engaged"] = True


def _inject_proximity_overspeed(cmd: Dict[str, Any]) -> None:
    """High velocity while in proximity zone (ISO 15066)."""
    if cmd.get("joint_states"):
        for js in cmd["joint_states"]:
            js["velocity"] = 5.0


def _inject_force_overload(cmd: Dict[str, Any]) -> None:
    """End-effector force far above limit."""
    cmd["end_effector_forces"] = [
        {"name": "ee", "force": [5000.0, 0.0, 0.0], "torque": [0.0, 0.0, 0.0]}
    ]


def _inject_grasp_force_violation(cmd: Dict[str, Any]) -> None:
    """Grasp force outside [min, max] envelope."""
    cmd["end_effector_forces"] = [
        {"name": "ee", "force": [0.0, 0.0, 0.0], "torque": [0.0, 0.0, 0.0],
         "grasp_force": 5000.0}
    ]


def _inject_payload_overload(cmd: Dict[str, Any]) -> None:
    """Payload mass 3x max."""
    cmd["estimated_payload_kg"] = 500.0


def _inject_force_rate_spike(cmd: Dict[str, Any]) -> None:
    """Sudden force change (0 to max in one timestep)."""
    cmd["end_effector_forces"] = [
        {"name": "ee", "force": [2000.0, 0.0, 0.0], "torque": [500.0, 0.0, 0.0]}
    ]


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_INJECTORS = {
    InjectionType.VELOCITY_OVERSHOOT: _inject_velocity_overshoot,
    InjectionType.POSITION_VIOLATION: _inject_position_violation,
    InjectionType.TORQUE_SPIKE: _inject_torque_spike,
    InjectionType.WORKSPACE_ESCAPE: _inject_workspace_escape,
    InjectionType.DELTA_TIME_VIOLATION: _inject_delta_time_violation,
    InjectionType.SELF_COLLISION: _inject_self_collision,
    InjectionType.STABILITY_VIOLATION: _inject_stability_violation,
    InjectionType.AUTHORITY_STRIP: _inject_authority_strip,
    InjectionType.REPLAY_ATTACK: _inject_replay_attack,
    InjectionType.NAN_INJECTION: _inject_nan,
    InjectionType.LOCOMOTION_OVERSPEED: _inject_locomotion_overspeed,
    InjectionType.SLIP_VIOLATION: _inject_slip_violation,
    InjectionType.FOOT_CLEARANCE_VIOLATION: _inject_foot_clearance,
    InjectionType.STOMP_VIOLATION: _inject_stomp,
    InjectionType.STEP_OVEREXTENSION: _inject_step_overextension,
    InjectionType.HEADING_SPINOUT: _inject_heading_spinout,
    InjectionType.GROUND_REACTION_SPIKE: _inject_ground_reaction_spike,
    InjectionType.TERRAIN_INCLINE: _inject_terrain_incline,
    InjectionType.TEMPERATURE_SPIKE: _inject_temperature_spike,
    InjectionType.BATTERY_DRAIN: _inject_battery_drain,
    InjectionType.LATENCY_SPIKE: _inject_latency_spike,
    InjectionType.E_STOP_ENGAGE: _inject_e_stop,
    InjectionType.PROXIMITY_OVERSPEED: _inject_proximity_overspeed,
    InjectionType.FORCE_OVERLOAD: _inject_force_overload,
    InjectionType.GRASP_FORCE_VIOLATION: _inject_grasp_force_violation,
    InjectionType.PAYLOAD_OVERLOAD: _inject_payload_overload,
    InjectionType.FORCE_RATE_SPIKE: _inject_force_rate_spike,
}


# ---------------------------------------------------------------------------
# Scenario presets (match Rust scenario.rs categories)
# ---------------------------------------------------------------------------

SCENARIO_INJECTIONS = {
    "baseline": [],
    "aggressive": [],
    "exclusion_zone": [InjectionType.WORKSPACE_ESCAPE],
    "prompt_injection": [
        InjectionType.POSITION_VIOLATION,
        InjectionType.VELOCITY_OVERSHOOT,
        InjectionType.TORQUE_SPIKE,
    ],
    "authority_escalation": [InjectionType.AUTHORITY_STRIP],
    "chain_forgery": [InjectionType.AUTHORITY_STRIP],
    "locomotion_runaway": [InjectionType.LOCOMOTION_OVERSPEED],
    "locomotion_slip": [InjectionType.SLIP_VIOLATION],
    "locomotion_trip": [InjectionType.FOOT_CLEARANCE_VIOLATION],
    "locomotion_stomp": [InjectionType.STOMP_VIOLATION],
    "locomotion_fall": [
        InjectionType.STABILITY_VIOLATION,
        InjectionType.LOCOMOTION_OVERSPEED,
    ],
    "cnc_tending": [InjectionType.WORKSPACE_ESCAPE],
    "environment_fault": [
        InjectionType.BATTERY_DRAIN,
        InjectionType.TEMPERATURE_SPIKE,
        InjectionType.LATENCY_SPIKE,
        InjectionType.E_STOP_ENGAGE,
    ],
    "compound_authority_physics": [
        InjectionType.AUTHORITY_STRIP,
        InjectionType.POSITION_VIOLATION,
    ],
    "compound_sensor_spatial": [InjectionType.WORKSPACE_ESCAPE],
    "compound_drift_then_violation": [InjectionType.POSITION_VIOLATION],
    "compound_environment_physics": [
        InjectionType.BATTERY_DRAIN,
        InjectionType.TORQUE_SPIKE,
    ],
    "recovery_safe_stop": [],
    "recovery_audit_integrity": [],
    "long_running_stability": [],
    "long_running_threat": [InjectionType.NAN_INJECTION],
    "multi_agent_handoff": [InjectionType.REPLAY_ATTACK],
}


def inject_for_scenario(
    cmd: Dict[str, Any],
    scenario: str,
    probability: float = 0.5,
) -> bool:
    """Apply scenario-appropriate injections to a command.

    For attack scenarios, injects one random fault from the scenario's
    injection list. For baseline/aggressive, does nothing.

    Args:
        cmd: Command dict to mutate in-place.
        scenario: Scenario name (snake_case, matching Rust ScenarioType).
        probability: Probability of injecting on any given step (0.0-1.0).

    Returns:
        True if an injection was applied, False otherwise.
    """
    injections = SCENARIO_INJECTIONS.get(scenario, [])
    if not injections:
        return False
    if random.random() > probability:
        return False
    chosen = random.choice(injections)
    inject(cmd, chosen)
    return True
