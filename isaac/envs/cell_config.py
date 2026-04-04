"""CNC tending cell constants (Sections 2.2, 4.2, 6.2).

All coordinates in meters. Origin (0,0,0) is the center of the UR10e base
mount on the shop floor.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Equipment positions (Section 2.2)
# ---------------------------------------------------------------------------

EQUIPMENT = {
    "ur10e_base": {"position": (0.0, 0.0, 0.0), "description": "UR10e base mount"},
    "haas_vf2ss": {
        "position": (-0.8, 0.3, 0.0),
        "dimensions": (3.1, 1.7, 2.5),
        "weight_kg": 3630.0,
    },
    "haas_vise": {
        "position": (-0.6, 0.3, 0.9),
        "dimensions": (0.15, 0.1, 0.08),
    },
    "raw_stock_pallet": {
        "position": (0.4, -0.3, 0.75),
        "dimensions": (0.4, 0.3, 0.1),
    },
    "finished_pallet": {
        "position": (0.4, 0.3, 0.75),
        "dimensions": (0.4, 0.3, 0.1),
    },
    "edge_pc": {
        "position": (0.5, 0.0, 1.0),
        "dimensions": (0.3, 0.2, 0.15),
        "weight_kg": 2.0,
    },
}

# ---------------------------------------------------------------------------
# Waypoints (Section 4.2)
# ---------------------------------------------------------------------------

WAYPOINTS: Dict[str, Tuple[float, float, float]] = {
    "W0_home": (0.0, -0.3, 1.2),
    "W1_stock_pick_approach": (0.4, -0.3, 0.9),
    "W2_stock_pick": (0.4, -0.3, 0.78),
    "W3_stock_lift": (0.4, -0.3, 0.95),
    "W4_door_approach": (-0.3, 0.2, 0.95),
    "W5_vise_approach": (-0.55, 0.3, 0.95),
    "W6_vise_place": (-0.55, 0.3, 0.9),
    "W7_vise_retreat": (-0.3, 0.2, 0.95),
    "W8_vise_pick": (-0.55, 0.3, 0.9),
    "W9_finished_approach": (0.4, 0.3, 0.95),
    "W10_finished_place": (0.4, 0.3, 0.78),
    "W11_finished_retreat": (0.4, 0.3, 0.95),
}

# ---------------------------------------------------------------------------
# UR10e joint names and home position
# ---------------------------------------------------------------------------

JOINT_NAMES: List[str] = [
    "shoulder_pan_joint",
    "shoulder_lift_joint",
    "elbow_joint",
    "wrist_1_joint",
    "wrist_2_joint",
    "wrist_3_joint",
]

HOME_JOINT_POSITIONS: Dict[str, float] = {
    "shoulder_pan_joint": 0.0,
    "shoulder_lift_joint": -1.571,
    "elbow_joint": 1.571,
    "wrist_1_joint": -1.571,
    "wrist_2_joint": 0.0,
    "wrist_3_joint": 0.0,
}

# ---------------------------------------------------------------------------
# Billet dimensions (Section 6.1)
# ---------------------------------------------------------------------------

BILLET_DIMENSIONS = (0.127, 0.076, 0.051)  # meters (5" x 3" x 2")
BILLET_MASS_KG = 1.6  # stainless steel billet

# ---------------------------------------------------------------------------
# Physics configuration (Section 6.2)
# ---------------------------------------------------------------------------

SIM_TIMESTEP_S = 1.0 / 120.0  # 120 Hz
GRAVITY_Z = -9.81  # m/s^2

FRICTION_BILLET_GRIPPER = {"static": 0.4, "kinetic": 0.3}
FRICTION_BILLET_VISE = {"static": 0.6, "kinetic": 0.5}

# Haas machining time per workpiece (simulated).
HAAS_CYCLE_TIME_S = 40.0 * 60.0  # 40 minutes

# Heartbeat interval for Invariant watchdog.
HEARTBEAT_INTERVAL_S = 0.05  # 50 ms (well within 100 ms timeout)

# Maximum number of billets on the stock pallet.
DEFAULT_BILLETS = 15

# ---------------------------------------------------------------------------
# Haas state machine (Section 5.2)
# ---------------------------------------------------------------------------


class HaasState(Enum):
    """External Haas VF-2SS machine state."""

    IDLE = auto()         # Machine idle, door open, safe to enter
    CUTTING = auto()      # Machining in progress, door closed
    COMPLETE = auto()     # Cycle complete, door opening/open


# ---------------------------------------------------------------------------
# Gripper state
# ---------------------------------------------------------------------------


class GripperState(Enum):
    OPEN = auto()
    CLOSED = auto()


# ---------------------------------------------------------------------------
# Cycle state (mirrors Rust CycleCoordinator, Section 5.1)
# ---------------------------------------------------------------------------


class CycleState(Enum):
    IDLE = auto()
    PICK_APPROACH = auto()
    PICK_BILLET = auto()
    PICK_LIFT = auto()
    CHECK_HAAS_READY = auto()
    WAIT_HAAS_READY = auto()
    DOOR_APPROACH = auto()
    VISE_APPROACH = auto()
    VISE_PLACE = auto()
    VISE_CLAMP = auto()
    VISE_RETREAT = auto()
    SIGNAL_HAAS_START = auto()
    WAIT_MACHINING = auto()
    VISE_UNCLAMP = auto()
    PICK_FINISHED = auto()
    FINISHED_APPROACH = auto()
    PLACE_DONE = auto()
    CHECK_STOCK = auto()
    CYCLE_COMPLETE = auto()


# Cycle phases where the haas_spindle_zone exclusion is DISABLED so the
# robot can enter the enclosure for loading/unloading.
SPINDLE_ZONE_DISABLED_STATES = frozenset({
    CycleState.DOOR_APPROACH,
    CycleState.VISE_APPROACH,
    CycleState.VISE_PLACE,
    CycleState.VISE_CLAMP,
    CycleState.VISE_UNCLAMP,
    CycleState.PICK_FINISHED,
})


@dataclass
class CycleStats:
    """Tracks cycle progress across a simulation episode."""

    billets_loaded: int = 0
    billets_machined: int = 0
    commands_sent: int = 0
    commands_approved: int = 0
    commands_rejected: int = 0
    heartbeats_sent: int = 0
    safe_stops: int = 0
