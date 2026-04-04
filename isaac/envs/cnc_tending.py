"""CNC tending environment for NVIDIA Isaac Lab.

File: isaac/envs/cnc_tending.py
Spec: Section 5-7

This module implements the Isaac Lab environment for the UR10e + Haas VF-2SS
CNC tending cell. It manages:

  1. Cell geometry and equipment placement (Section 2.2)
  2. Haas VF-2SS state machine: IDLE -> CUTTING -> COMPLETE (Section 5.1)
  3. Cycle coordinator: 19-state tending cycle (Section 5.1)
  4. Communication with Invariant via Unix socket IPC (Section 7.2)
  5. Observation/command protocol for the simulation loop

The environment does NOT make safety decisions -- Invariant does. Every
joint command passes through the Invariant bridge for validation before
being applied to the simulated robot.

Requires: NVIDIA Isaac Sim / Isaac Lab (for actual simulation).
Without Isaac Sim, this module can still be imported and unit-tested
for state machine logic, protocol formatting, and cycle sequencing.
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .cell_config import (
    BILLET_DIMENSIONS,
    BILLET_MASS_KG,
    CycleState,
    CycleStats,
    DEFAULT_BILLETS,
    GripperState,
    HAAS_CYCLE_TIME_S,
    HaasState,
    HEARTBEAT_INTERVAL_S,
    HOME_JOINT_POSITIONS,
    JOINT_NAMES,
    SIM_TIMESTEP_S,
    SPINDLE_ZONE_DISABLED_STATES,
    WAYPOINTS,
)

logger = logging.getLogger(__name__)

# Conditional import: Isaac Lab is only available inside Isaac Sim.
try:
    from omni.isaac.lab.envs import DirectRLEnv  # type: ignore[import]

    _HAS_ISAAC = True
except ImportError:
    _HAS_ISAAC = False

# Conditional import: the Invariant bridge client.
try:
    import sys
    import os

    # The bridge client ships at crates/invariant-sim/invariant_isaac_bridge.py
    _bridge_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "crates", "invariant-sim"
    )
    if os.path.isdir(_bridge_dir):
        sys.path.insert(0, _bridge_dir)
    from invariant_isaac_bridge import InvariantBridge  # type: ignore[import]

    _HAS_BRIDGE = True
except ImportError:
    _HAS_BRIDGE = False


# ---------------------------------------------------------------------------
# Observation dataclass
# ---------------------------------------------------------------------------


@dataclass
class CellObservation:
    """Observation returned after each simulation step (Section 7.2)."""

    timestamp_ns: int
    joint_positions: Dict[str, float]
    joint_velocities: Dict[str, float]
    joint_efforts: Dict[str, float]
    end_effector_position: Tuple[float, float, float]
    force_torque: Tuple[float, float, float, float, float, float]
    haas_state: str
    gripper_state: str
    billet_in_gripper: bool
    billets_remaining: int
    cycle_state: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the Section 7.2 JSON observation format."""
        return {
            "type": "observation",
            "timestamp_ns": self.timestamp_ns,
            "joint_states": {
                name: {
                    "position": self.joint_positions[name],
                    "velocity": self.joint_velocities[name],
                    "effort": self.joint_efforts[name],
                }
                for name in JOINT_NAMES
            },
            "end_effector_position": list(self.end_effector_position),
            "force_torque": list(self.force_torque),
            "haas_state": self.haas_state,
            "gripper_state": self.gripper_state,
            "billet_in_gripper": self.billet_in_gripper,
            "billets_remaining": self.billets_remaining,
            "cycle_state": self.cycle_state,
        }


# ---------------------------------------------------------------------------
# Invariant command builder
# ---------------------------------------------------------------------------


def build_invariant_command(
    joint_positions: Dict[str, float],
    joint_velocities: Dict[str, float],
    joint_efforts: Dict[str, float],
    ee_position: Tuple[float, float, float],
    delta_time: float,
    sequence: int,
    pca_chain_b64: str,
    required_ops: List[str],
    zone_overrides: Optional[Dict[str, bool]] = None,
    source: str = "isaac_lab",
    estimated_payload_kg: Optional[float] = None,
) -> Dict[str, Any]:
    """Build an Invariant Command JSON dict matching the Rust Command schema.

    This produces the exact JSON structure that bridge.rs expects, matching
    crates/invariant-core/src/models/command.rs.
    """
    now = datetime.now(timezone.utc).isoformat()
    cmd: Dict[str, Any] = {
        "timestamp": now,
        "source": source,
        "sequence": sequence,
        "joint_states": [
            {
                "name": name,
                "position": joint_positions[name],
                "velocity": joint_velocities[name],
                "effort": joint_efforts[name],
            }
            for name in JOINT_NAMES
        ],
        "delta_time": delta_time,
        "end_effector_positions": [
            {
                "name": "gripper",
                "position": list(ee_position),
            }
        ],
        "authority": {
            "pca_chain": pca_chain_b64,
            "required_ops": list(required_ops),
        },
    }
    if zone_overrides:
        cmd["zone_overrides"] = zone_overrides
    if estimated_payload_kg is not None:
        cmd["estimated_payload_kg"] = estimated_payload_kg
    return cmd


# ---------------------------------------------------------------------------
# Haas VF-2SS simulator (Section 5.2)
# ---------------------------------------------------------------------------


class HaasSimulator:
    """Simulates the Haas VF-2SS CNC machine state transitions.

    In the real cell, these transitions are driven by M-code digital I/O
    signals. In simulation, they are timer-based.
    """

    def __init__(self, cycle_time_s: float = HAAS_CYCLE_TIME_S):
        self.state = HaasState.IDLE
        self.cycle_time_s = cycle_time_s
        self._elapsed_cutting_s: float = 0.0

    @property
    def is_ready(self) -> bool:
        return self.state == HaasState.IDLE

    @property
    def is_cutting(self) -> bool:
        return self.state == HaasState.CUTTING

    @property
    def is_complete(self) -> bool:
        return self.state == HaasState.COMPLETE

    def start_cycle(self) -> None:
        """Signal HAAS_CYCLE_START (edge PC -> Haas)."""
        if self.state != HaasState.IDLE:
            raise RuntimeError(
                f"Cannot start cycle: Haas is {self.state.name}, not IDLE"
            )
        self.state = HaasState.CUTTING
        self._elapsed_cutting_s = 0.0
        logger.info("Haas cycle started")

    def step(self, dt_s: float) -> None:
        """Advance the Haas simulator by dt_s seconds."""
        if self.state == HaasState.CUTTING:
            self._elapsed_cutting_s += dt_s
            if self._elapsed_cutting_s >= self.cycle_time_s:
                self.state = HaasState.COMPLETE
                logger.info(
                    "Haas cycle complete after %.1f s",
                    self._elapsed_cutting_s,
                )

    def acknowledge_complete(self) -> None:
        """Operator/coordinator acknowledges cycle complete, resets to IDLE."""
        if self.state != HaasState.COMPLETE:
            raise RuntimeError(
                f"Cannot acknowledge: Haas is {self.state.name}, not COMPLETE"
            )
        self.state = HaasState.IDLE
        self._elapsed_cutting_s = 0.0
        logger.info("Haas reset to IDLE")

    def reset(self) -> None:
        """Force reset to IDLE (for episode reset)."""
        self.state = HaasState.IDLE
        self._elapsed_cutting_s = 0.0


# ---------------------------------------------------------------------------
# Cycle coordinator (mirrors Rust invariant-core::cycle, Section 5.1)
# ---------------------------------------------------------------------------


class CycleCoordinator:
    """Manages the CNC tending cycle state machine.

    This is the Python-side mirror of the Rust CycleCoordinator. It tracks
    the cycle phase, manages zone overrides for the haas_spindle_zone
    conditional exclusion, and issues actuator commands (gripper, vise,
    Haas signals).
    """

    def __init__(
        self,
        num_billets: int = DEFAULT_BILLETS,
        spindle_zone_name: str = "haas_spindle_zone",
    ):
        self.state = CycleState.IDLE
        self.billets_remaining = num_billets
        self.parts_completed = 0
        self.spindle_zone_name = spindle_zone_name

    @property
    def zone_overrides(self) -> Dict[str, bool]:
        """Current exclusion zone override map for Invariant commands.

        The spindle zone is disabled (False) during loading/unloading phases
        so the robot can enter the Haas enclosure. It is active (True) or
        absent during all other phases (fail-closed).
        """
        if self.state in SPINDLE_ZONE_DISABLED_STATES:
            return {self.spindle_zone_name: False}
        return {}

    @property
    def target_waypoint(self) -> Optional[str]:
        """The waypoint the robot should be moving toward in this state."""
        mapping = {
            CycleState.IDLE: "W0_home",
            CycleState.PICK_APPROACH: "W1_stock_pick_approach",
            CycleState.PICK_BILLET: "W2_stock_pick",
            CycleState.PICK_LIFT: "W3_stock_lift",
            CycleState.CHECK_HAAS_READY: "W3_stock_lift",
            CycleState.WAIT_HAAS_READY: "W3_stock_lift",
            CycleState.DOOR_APPROACH: "W4_door_approach",
            CycleState.VISE_APPROACH: "W5_vise_approach",
            CycleState.VISE_PLACE: "W6_vise_place",
            CycleState.VISE_CLAMP: "W6_vise_place",
            CycleState.VISE_RETREAT: "W7_vise_retreat",
            CycleState.SIGNAL_HAAS_START: "W7_vise_retreat",
            CycleState.WAIT_MACHINING: "W0_home",
            CycleState.VISE_UNCLAMP: "W6_vise_place",
            CycleState.PICK_FINISHED: "W8_vise_pick",
            CycleState.FINISHED_APPROACH: "W9_finished_approach",
            CycleState.PLACE_DONE: "W10_finished_place",
            CycleState.CHECK_STOCK: "W11_finished_retreat",
            CycleState.CYCLE_COMPLETE: "W0_home",
        }
        return mapping.get(self.state)

    def advance(
        self, haas: "HaasSimulator", gripper: GripperState
    ) -> Tuple[CycleState, List[str]]:
        """Advance the cycle state machine. Returns (new_state, commands).

        Commands are string identifiers for actuator actions the environment
        should execute before the next step.
        """
        commands: List[str] = []
        prev = self.state

        if self.state == CycleState.IDLE:
            if self.billets_remaining > 0:
                self.state = CycleState.PICK_APPROACH

        elif self.state == CycleState.PICK_APPROACH:
            self.state = CycleState.PICK_BILLET
            commands.append("GRIPPER_OPEN")

        elif self.state == CycleState.PICK_BILLET:
            commands.append("GRIPPER_CLOSE")
            self.billets_remaining -= 1
            self.state = CycleState.PICK_LIFT

        elif self.state == CycleState.PICK_LIFT:
            self.state = CycleState.CHECK_HAAS_READY

        elif self.state == CycleState.CHECK_HAAS_READY:
            if haas.is_ready:
                self.state = CycleState.DOOR_APPROACH
            else:
                self.state = CycleState.WAIT_HAAS_READY

        elif self.state == CycleState.WAIT_HAAS_READY:
            if haas.is_ready:
                self.state = CycleState.DOOR_APPROACH

        elif self.state == CycleState.DOOR_APPROACH:
            self.state = CycleState.VISE_APPROACH

        elif self.state == CycleState.VISE_APPROACH:
            self.state = CycleState.VISE_PLACE

        elif self.state == CycleState.VISE_PLACE:
            commands.append("GRIPPER_OPEN")
            self.state = CycleState.VISE_CLAMP

        elif self.state == CycleState.VISE_CLAMP:
            commands.append("VISE_CLAMP")
            self.state = CycleState.VISE_RETREAT

        elif self.state == CycleState.VISE_RETREAT:
            self.state = CycleState.SIGNAL_HAAS_START

        elif self.state == CycleState.SIGNAL_HAAS_START:
            commands.append("HAAS_CYCLE_START")
            self.state = CycleState.WAIT_MACHINING

        elif self.state == CycleState.WAIT_MACHINING:
            if haas.is_complete:
                haas.acknowledge_complete()
                self.state = CycleState.VISE_UNCLAMP

        elif self.state == CycleState.VISE_UNCLAMP:
            commands.append("VISE_UNCLAMP")
            self.state = CycleState.PICK_FINISHED

        elif self.state == CycleState.PICK_FINISHED:
            commands.append("GRIPPER_CLOSE")
            self.state = CycleState.FINISHED_APPROACH

        elif self.state == CycleState.FINISHED_APPROACH:
            self.state = CycleState.PLACE_DONE

        elif self.state == CycleState.PLACE_DONE:
            commands.append("GRIPPER_OPEN")
            self.parts_completed += 1
            self.state = CycleState.CHECK_STOCK

        elif self.state == CycleState.CHECK_STOCK:
            if self.billets_remaining > 0:
                self.state = CycleState.PICK_APPROACH
            else:
                self.state = CycleState.CYCLE_COMPLETE

        if prev != self.state:
            logger.debug("Cycle: %s -> %s", prev.name, self.state.name)

        return self.state, commands

    def reset(self, num_billets: Optional[int] = None) -> None:
        """Reset for a new episode."""
        self.state = CycleState.IDLE
        if num_billets is not None:
            self.billets_remaining = num_billets
        self.parts_completed = 0


# ---------------------------------------------------------------------------
# Trajectory interpolator
# ---------------------------------------------------------------------------


def interpolate_waypoint(
    current_ee: Tuple[float, float, float],
    target_ee: Tuple[float, float, float],
    max_step_m: float = 0.01,
) -> Tuple[float, float, float]:
    """Move end-effector one step toward target, clamped to max_step_m.

    Returns the next EE position. When within max_step_m of the target,
    returns the target exactly.
    """
    dx = target_ee[0] - current_ee[0]
    dy = target_ee[1] - current_ee[1]
    dz = target_ee[2] - current_ee[2]
    dist = math.sqrt(dx * dx + dy * dy + dz * dz)
    if dist <= max_step_m:
        return target_ee
    scale = max_step_m / dist
    return (
        current_ee[0] + dx * scale,
        current_ee[1] + dy * scale,
        current_ee[2] + dz * scale,
    )


# ---------------------------------------------------------------------------
# Main environment
# ---------------------------------------------------------------------------


class CncTendingEnv:
    """Isaac Lab environment for UR10e + Haas VF-2 CNC tending.

    This environment:
      1. Spawns the UR10e, Haas enclosure, vise, pallets, and billets
      2. Receives joint commands from Invariant (via Unix socket IPC)
      3. Steps the physics simulation
      4. Returns joint states, end-effector position, and force/torque
      5. Manages Haas state machine (idle -> cutting -> complete)

    Invariant runs as an external process, connected via Unix socket.
    The environment does NOT make safety decisions -- Invariant does.

    When Isaac Sim is not available, the environment runs in "dry-run"
    mode: no physics simulation, just state machine + protocol logic.
    """

    def __init__(
        self,
        num_envs: int = 1,
        num_billets: int = DEFAULT_BILLETS,
        haas_cycle_time_s: float = HAAS_CYCLE_TIME_S,
        socket_path: str = "/tmp/invariant.sock",
        pca_chain_b64: str = "",
        required_ops: Optional[List[str]] = None,
        connect_bridge: bool = False,
    ):
        """Initialize the CNC tending environment.

        Args:
            num_envs: Number of parallel environments (for GPU batching).
            num_billets: Billets on the stock pallet at episode start.
            haas_cycle_time_s: Simulated Haas machining time per part.
            socket_path: Unix socket for the Invariant bridge.
            pca_chain_b64: Base64-encoded PCA authority chain.
            required_ops: Operation patterns for command authority.
            connect_bridge: Whether to connect to Invariant on init.
        """
        self.num_envs = num_envs
        self.num_billets = num_billets
        self.haas_cycle_time_s = haas_cycle_time_s
        self.socket_path = socket_path
        self.pca_chain_b64 = pca_chain_b64
        self.required_ops = required_ops or ["actuate:*"]

        # Per-environment state (index 0 for single-env; extend for parallel).
        self.haas = HaasSimulator(cycle_time_s=haas_cycle_time_s)
        self.cycle = CycleCoordinator(
            num_billets=num_billets, spindle_zone_name="haas_spindle_zone"
        )
        self.gripper = GripperState.OPEN
        self.billet_in_gripper = False

        # Simulated robot state.
        self.joint_positions: Dict[str, float] = dict(HOME_JOINT_POSITIONS)
        self.joint_velocities: Dict[str, float] = {n: 0.0 for n in JOINT_NAMES}
        self.joint_efforts: Dict[str, float] = {n: 0.0 for n in JOINT_NAMES}
        self.ee_position: Tuple[float, float, float] = WAYPOINTS["W0_home"]
        self.force_torque = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        # Sequence counter for Invariant commands.
        self._sequence: int = 0
        self._sim_time_s: float = 0.0
        self._last_heartbeat_s: float = 0.0
        self._episode_stats = CycleStats()

        # Bridge connection (lazy).
        self._bridge: Optional[Any] = None
        if connect_bridge:
            self._connect_bridge()

    # ------------------------------------------------------------------
    # Bridge connection
    # ------------------------------------------------------------------

    def _connect_bridge(self) -> None:
        """Connect to the Invariant Unix socket bridge."""
        if not _HAS_BRIDGE:
            raise ImportError(
                "invariant_isaac_bridge not found. Ensure "
                "crates/invariant-sim/invariant_isaac_bridge.py is on "
                "sys.path or install it."
            )
        self._bridge = InvariantBridge(self.socket_path)
        logger.info("Connected to Invariant bridge at %s", self.socket_path)

    # ------------------------------------------------------------------
    # Episode lifecycle
    # ------------------------------------------------------------------

    def reset(self, num_billets: Optional[int] = None) -> CellObservation:
        """Reset the environment for a new episode.

        Returns the initial observation.
        """
        billets = num_billets if num_billets is not None else self.num_billets
        self.haas.reset()
        self.cycle.reset(num_billets=billets)
        self.gripper = GripperState.OPEN
        self.billet_in_gripper = False
        self.joint_positions = dict(HOME_JOINT_POSITIONS)
        self.joint_velocities = {n: 0.0 for n in JOINT_NAMES}
        self.joint_efforts = {n: 0.0 for n in JOINT_NAMES}
        self.ee_position = WAYPOINTS["W0_home"]
        self.force_torque = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        # Keep _sequence monotonic across episodes (never reset while bridge
        # is alive) so audit logs and threat scoring see a clean timeline.
        self._sim_time_s = 0.0
        self._last_heartbeat_s = 0.0
        self._episode_stats = CycleStats()
        return self._observe()

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def _observe(self) -> CellObservation:
        """Build the current observation."""
        return CellObservation(
            timestamp_ns=int(self._sim_time_s * 1e9),
            joint_positions=dict(self.joint_positions),
            joint_velocities=dict(self.joint_velocities),
            joint_efforts=dict(self.joint_efforts),
            end_effector_position=self.ee_position,
            force_torque=self.force_torque,
            haas_state=self.haas.state.name,
            gripper_state=self.gripper.name,
            billet_in_gripper=self.billet_in_gripper,
            billets_remaining=self.cycle.billets_remaining,
            cycle_state=self.cycle.state.name,
        )

    # ------------------------------------------------------------------
    # Step: advance simulation + validate through Invariant
    # ------------------------------------------------------------------

    def step(
        self,
        target_joint_positions: Optional[Dict[str, float]] = None,
        target_ee_position: Optional[Tuple[float, float, float]] = None,
    ) -> Tuple[CellObservation, Dict[str, Any]]:
        """Execute one simulation step.

        Either target_joint_positions or target_ee_position should be
        provided. If neither is given, the robot holds its current position.

        Returns (observation, info_dict).
        """
        dt = SIM_TIMESTEP_S
        self._sim_time_s += dt

        # Advance Haas machining timer.
        self.haas.step(dt)

        # Build the target joint state. In a full Isaac Lab environment,
        # these come from an IK solver or RL policy. In dry-run mode we
        # use the current positions (hold still) or interpolate to a
        # waypoint if target_ee_position is given.
        if target_joint_positions is not None:
            proposed_positions = dict(target_joint_positions)
        else:
            proposed_positions = dict(self.joint_positions)

        # Use the target EE position to update the simulated EE (no IK
        # in dry-run mode, just direct placement for protocol testing).
        if target_ee_position is not None:
            self.ee_position = interpolate_waypoint(
                self.ee_position, target_ee_position
            )

        # Estimate payload for P14 check.
        payload = BILLET_MASS_KG if self.billet_in_gripper else None

        # Build command for Invariant.
        self._sequence += 1
        cmd = build_invariant_command(
            joint_positions=proposed_positions,
            joint_velocities=self.joint_velocities,
            joint_efforts=self.joint_efforts,
            ee_position=self.ee_position,
            delta_time=dt,
            sequence=self._sequence,
            pca_chain_b64=self.pca_chain_b64,
            required_ops=self.required_ops,
            zone_overrides=self.cycle.zone_overrides,
            estimated_payload_kg=payload,
        )

        # Validate through Invariant bridge (if connected).
        verdict: Dict[str, Any] = {}
        approved = True  # Default: approved in dry-run mode

        if self._bridge is not None:
            verdict = self._bridge.validate(cmd)
            approved = verdict.get("approved", False)
            self._episode_stats.commands_sent += 1
            if approved:
                self._episode_stats.commands_approved += 1
            else:
                self._episode_stats.commands_rejected += 1
        else:
            self._episode_stats.commands_sent += 1
            self._episode_stats.commands_approved += 1

        # Apply the command if approved, otherwise hold position.
        if approved and target_joint_positions is not None:
            self.joint_positions = proposed_positions

        # Send heartbeat if needed.
        if self._sim_time_s - self._last_heartbeat_s >= HEARTBEAT_INTERVAL_S:
            if self._bridge is not None:
                self._bridge.heartbeat()
            self._episode_stats.heartbeats_sent += 1
            self._last_heartbeat_s = self._sim_time_s

        info = {
            "approved": approved,
            "verdict": verdict,
            "cycle_state": self.cycle.state.name,
            "haas_state": self.haas.state.name,
            "sim_time_s": self._sim_time_s,
        }

        return self._observe(), info

    # ------------------------------------------------------------------
    # Cycle step: advance the tending state machine and step physics
    # ------------------------------------------------------------------

    def cycle_step(self) -> Tuple[CellObservation, Dict[str, Any]]:
        """Advance the cycle coordinator and step toward the target waypoint.

        This is the high-level step that a campaign runner calls. It:
          1. Advances the cycle state machine
          2. Executes actuator commands (gripper, vise, Haas signals)
          3. Steps the simulation toward the target waypoint
          4. Validates through Invariant

        Returns (observation, info_dict).
        """
        # Advance cycle state machine.
        new_state, commands = self.cycle.advance(self.haas, self.gripper)

        # Execute actuator commands.
        for cmd_str in commands:
            self._execute_actuator(cmd_str)

        # Get target waypoint and step toward it.
        wp_name = self.cycle.target_waypoint
        target_ee = WAYPOINTS.get(wp_name) if wp_name else None

        return self.step(target_ee_position=target_ee)

    def _execute_actuator(self, command: str) -> None:
        """Execute an actuator command from the cycle coordinator."""
        if command == "GRIPPER_CLOSE":
            self.gripper = GripperState.CLOSED
            # GRIPPER_CLOSE is only emitted during billet picks (stock or
            # vise), so we always hold a billet after closing.
            self.billet_in_gripper = True
        elif command == "GRIPPER_OPEN":
            self.gripper = GripperState.OPEN
            self.billet_in_gripper = False
        elif command == "VISE_CLAMP":
            logger.debug("Vise clamped")
        elif command == "VISE_UNCLAMP":
            logger.debug("Vise unclamped")
        elif command == "HAAS_CYCLE_START":
            self.haas.start_cycle()
        else:
            logger.warning("Unknown actuator command: %s", command)

    # ------------------------------------------------------------------
    # Run a full cycle (convenience for campaigns)
    # ------------------------------------------------------------------

    def run_single_billet_cycle(
        self, fast_forward_machining: bool = True
    ) -> CycleStats:
        """Run a complete single-billet tending cycle.

        This steps through the full 19-state cycle:
          pick billet -> load into Haas -> machine -> unload -> place finished

        Args:
            fast_forward_machining: If True, skip the simulated machining
                wait by directly completing the Haas cycle.

        Returns the episode statistics.
        """
        max_steps = 10_000  # Safety limit
        step_count = 0

        while (
            self.cycle.state != CycleState.CYCLE_COMPLETE
            and step_count < max_steps
        ):
            # Fast-forward machining wait to avoid 40-minute sim time.
            if fast_forward_machining and self.cycle.state == CycleState.WAIT_MACHINING:
                self.haas._elapsed_cutting_s = self.haas.cycle_time_s
                self.haas.step(0.0)  # Trigger COMPLETE

            self.cycle_step()
            step_count += 1

        return self._episode_stats

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_done(self) -> bool:
        """Whether the episode is complete (all billets processed)."""
        return self.cycle.state == CycleState.CYCLE_COMPLETE

    @property
    def stats(self) -> CycleStats:
        return self._episode_stats

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the bridge connection and clean up."""
        if self._bridge is not None:
            self._bridge.close()
            self._bridge = None

    def __enter__(self) -> "CncTendingEnv":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"CncTendingEnv(num_envs={self.num_envs}, "
            f"billets={self.cycle.billets_remaining}, "
            f"cycle={self.cycle.state.name}, "
            f"haas={self.haas.state.name})"
        )
