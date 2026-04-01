# Good Luck LLC — CNC Cell Simulation Specification

## Document Purpose

This is the exhaustive specification for simulating the Good Luck LLC manufacturing cell (Haas VF-2SS + UR10e + Beelink/Invariant) in NVIDIA Isaac Sim. It defines the cell geometry, the UR10e safety profile for CNC tending, the Haas enclosure model, the cycle sequence, the I/O protocol, and the 1M-episode simulation campaign.

**This spec bridges the gap between Invariant (the software) and Good Luck LLC (the business).** Everything in this document is buildable from the existing Invariant codebase + Isaac Sim.

---

## 1. Current Software Status

Based on codebase analysis (April 2026):

| Component | Status | Files | Notes |
|-----------|--------|-------|-------|
| Physics checks P1-P20 | **100% done** | `crates/invariant-core/src/physics/` | All 20 checks implemented with tests |
| Validator orchestrator | **100% done** | `crates/invariant-core/src/validator.rs` | 912 lines, 18+ tests |
| Watchdog | **100% done** | `crates/invariant-core/src/watchdog.rs` | 539 lines, clock regression protection |
| Audit system | **100% done** | `crates/invariant-core/src/audit.rs` | Hash chain, Ed25519 signing, verification |
| Authority/PIC chain | **100% done** | `crates/invariant-core/src/authority/` | Full PIC validation |
| UR10 profile | **100% done** | `profiles/ur10.json` | 6 joints, workspace, exclusion zones |
| Campaign runner (dry-run) | **100% done** | `crates/invariant-sim/src/` | Scenarios, injection, reporting |
| Isaac Lab bridge | **~5% stub** | `crates/invariant-sim/src/isaac/bridge.rs` | 15-line sketch. **THIS IS THE MAIN WORK.** |

**You are ~90% done on the software. Not 40%.** The remaining work is:
1. Build the Isaac Lab bridge (connect Invariant to Isaac Sim via Unix socket IPC)
2. Create the Good Luck LLC cell environment in Isaac Sim
3. Write the CNC-tending-specific UR10e profile (adapt from `ur10.json`)
4. Configure the 1M-episode campaign
5. Run it

---

## 2. Physical Cell Specification

### 2.1 Coordinate System

All coordinates in meters. Origin (0,0,0) is the center of the UR10e base mount on the shop floor.

```
        +Y (toward back wall)
        │
        │
        │     +Z (up)
        │    /
        │   /
        │  /
        │ /
        └──────────── +X (toward overhead door)
      (0,0,0)
      UR10e base
```

### 2.2 Equipment Positions

| Equipment | Position (center, m) | Dimensions (m) | Weight |
|-----------|---------------------|-----------------|--------|
| UR10e base mount | (0, 0, 0) on floor pedestal | Base: 0.19m dia, Height on pedestal: 0.75m | 33.5 kg (arm) |
| Haas VF-2SS | (-0.8, 0.3, 0) center of enclosure | 3.1 x 1.7 x 2.5 (L x W x H) | 3,630 kg |
| Haas vise (work area) | (-0.6, 0.3, 0.9) center of vise jaws | 0.15 x 0.1 x 0.08 (jaw opening) | N/A |
| Raw stock pallet | (0.4, -0.3, 0.75) on a table/stand | 0.4 x 0.3 x 0.1 (pallet surface) | Holds 10-20 billets |
| Finished parts pallet | (0.4, 0.3, 0.75) on a table/stand | 0.4 x 0.3 x 0.1 (pallet surface) | Holds 10-20 blocks |
| Beelink (NEMA enclosure) | (0.5, 0, 1.0) wall-mounted | 0.3 x 0.2 x 0.15 | 2 kg |
| Pneumatic vise actuator | On vise body | Integrated | Part of vise |

### 2.3 UR10e Reach Analysis

| Target | Distance from UR10e base | Within 1300mm reach? |
|--------|-------------------------|---------------------|
| Haas vise center | ~1,000 mm | Yes (77% of max reach) |
| Raw stock pallet center | ~580 mm | Yes (45% of max reach) |
| Finished parts pallet center | ~580 mm | Yes (45% of max reach) |
| Haas door handle (if needed) | ~900 mm | Yes (69% of max reach) |

All targets are comfortably within the UR10e's 1,300mm reach. The robot does not need to fully extend for any operation.

---

## 3. UR10e CNC Tending Profile

### 3.1 Profile: `profiles/ur10e_cnc_tending.json`

This is a NEW profile adapted from the existing `ur10.json`, customized for the Good Luck LLC manufacturing cell. The joint limits are identical (they're hardware constraints); the workspace, exclusion zones, and safe-stop are cell-specific.

```json
{
  "name": "ur10e_cnc_tending",
  "version": "1.0.0",
  "description": "UR10e safety profile for Good Luck LLC Haas VF-2SS CNC tending cell",

  "joints": [
    {
      "name": "shoulder_pan_joint",
      "type": "revolute",
      "min": -6.2832,
      "max": 6.2832,
      "max_velocity": 2.0944,
      "max_torque": 330.0,
      "max_acceleration": 10.0
    },
    {
      "name": "shoulder_lift_joint",
      "type": "revolute",
      "min": -6.2832,
      "max": 6.2832,
      "max_velocity": 2.0944,
      "max_torque": 330.0,
      "max_acceleration": 10.0
    },
    {
      "name": "elbow_joint",
      "type": "revolute",
      "min": -3.1416,
      "max": 3.1416,
      "max_velocity": 3.1416,
      "max_torque": 150.0,
      "max_acceleration": 10.0
    },
    {
      "name": "wrist_1_joint",
      "type": "revolute",
      "min": -6.2832,
      "max": 6.2832,
      "max_velocity": 3.1416,
      "max_torque": 56.0,
      "max_acceleration": 20.0
    },
    {
      "name": "wrist_2_joint",
      "type": "revolute",
      "min": -6.2832,
      "max": 6.2832,
      "max_velocity": 3.1416,
      "max_torque": 56.0,
      "max_acceleration": 20.0
    },
    {
      "name": "wrist_3_joint",
      "type": "revolute",
      "min": -6.2832,
      "max": 6.2832,
      "max_velocity": 3.1416,
      "max_torque": 56.0,
      "max_acceleration": 20.0
    }
  ],

  "workspace": {
    "type": "aabb",
    "min": [-1.2, -0.8, 0.0],
    "max": [0.8, 0.8, 1.8],
    "_comment": "Cell-specific workspace. Robot stays within the cell footprint."
  },

  "exclusion_zones": [
    {
      "type": "aabb",
      "name": "haas_spindle_area",
      "min": [-1.0, 0.0, 0.7],
      "max": [-0.3, 0.6, 1.5],
      "_comment": "Interior of Haas enclosure around spindle. NEVER enter during cut. Conditionally disabled when Haas signals cycle complete + door open."
    },
    {
      "type": "aabb",
      "name": "haas_enclosure_rear",
      "min": [-1.5, 0.5, 0.0],
      "max": [0.0, 1.2, 2.5],
      "_comment": "Rear and sides of Haas enclosure. Permanent exclusion - robot cannot reach behind machine."
    },
    {
      "type": "aabb",
      "name": "floor_zone",
      "min": [-1.5, -1.0, -0.1],
      "max": [1.0, 1.0, 0.05],
      "_comment": "Below floor level. Prevents robot from driving end-effector into the ground."
    },
    {
      "type": "aabb",
      "name": "beelink_enclosure",
      "min": [0.35, -0.15, 0.85],
      "max": [0.65, 0.15, 1.15],
      "_comment": "Beelink NEMA enclosure. Don't hit the safety computer."
    }
  ],

  "proximity_zones": [
    {
      "name": "haas_door_approach",
      "type": "sphere",
      "center": [-0.5, 0.1, 0.9],
      "radius": 0.4,
      "velocity_scale": 0.5,
      "dynamic": false,
      "_comment": "Slow down when approaching the Haas door/vise area. Precision zone."
    }
  ],

  "collision_pairs": [
    ["wrist_3_link", "base_link"],
    ["wrist_3_link", "shoulder_link"],
    ["forearm_link", "base_link"]
  ],

  "stability": null,

  "max_delta_time": 0.008,
  "min_collision_distance": 0.05,
  "global_velocity_scale": 1.0,

  "watchdog_timeout_ms": 100,

  "safe_stop_profile": {
    "strategy": "controlled_crouch",
    "max_deceleration": 8.0,
    "target_joint_positions": {
      "shoulder_pan_joint": 0.0,
      "shoulder_lift_joint": -1.571,
      "elbow_joint": 1.571,
      "wrist_1_joint": -1.571,
      "wrist_2_joint": 0.0,
      "wrist_3_joint": 0.0
    },
    "_comment": "Safe-stop position: arm folded upright, clear of all equipment. UR10e 'home' position."
  }
}
```

### 3.2 Conditional Exclusion Zone: Haas Spindle Area

The `haas_spindle_area` exclusion zone has a critical behavior: it is ENABLED when the Haas is cutting and DISABLED when the Haas signals cycle complete + door open. This prevents the robot from entering the enclosure during machining but allows it to load/unload parts.

**Implementation approach:** The exclusion zone is always defined in the profile. The cycle coordinator on the Beelink manages a `haas_state` variable:

```
haas_state = CUTTING   →  haas_spindle_area exclusion ACTIVE   → robot CANNOT enter
haas_state = DOOR_OPEN →  haas_spindle_area exclusion INACTIVE → robot CAN enter to load/unload
```

This requires a small extension to Invariant's exclusion zone logic: conditional zones that can be activated/deactivated by the cycle coordinator. The zone ID and state must be included in the command validation context.

**Spec for implementation:**
- Add an optional `conditional` field to exclusion zones in the profile
- Add a `zone_overrides: HashMap<String, bool>` to the Command struct
- In the exclusion zone check (P6), skip zones where `conditional = true` AND the override is `false` (zone disabled)
- The override MUST be set by the Beelink's cycle coordinator based on Haas I/O state — NOT by the cognitive layer
- Audit log every zone state change

---

## 4. Haas VF-2SS Model (For Simulation)

### 4.1 Enclosure Geometry

The Haas VF-2SS enclosure is modeled as a set of rigid body AABBs in Isaac Sim. The robot does not interact with the machine internals — only the door opening and the vise position matter.

```
HAAS VF-2SS ENCLOSURE (simplified for simulation)

        Top view (looking down):

        ┌──────────────────────────┐
        │                          │
        │    HAAS INTERIOR         │
        │    (exclusion zone       │
        │     when cutting)        │
        │                          │
        │    [ VISE ] ←load point  │
        │                          │
        │    [ SPINDLE ]           │
        │                          │
        ├──────┐          ┌────────┤
        │      │  DOOR    │        │
        │      │ OPENING  │        │
        │      └──────────┘        │
        └──────────────────────────┘

        Side view:

        ┌──────────────────────────┐ 2.5m
        │                          │
        │                          │
        │        [SPINDLE]         │
        │            │             │
        │            ▼             │
        │        [ VISE ]          │ 0.9m (vise height)
        │                          │
        └──┐                    ┌──┘
           │   DOOR OPENING     │    0.0m (floor)
           └────────────────────┘
             0.7m wide opening
```

### 4.2 Key Positions (Simulation Waypoints)

These are the positions the UR10e end-effector must reach during the cycle. In simulation, these are taught as waypoints. On real hardware, they're re-taught with ±5mm calibration.

| Waypoint | Name | Position (x, y, z) m | Description |
|----------|------|---------------------|-------------|
| W0 | Home | (0.0, -0.3, 1.2) | Safe home position. Clear of all equipment. |
| W1 | Stock pick approach | (0.4, -0.3, 0.9) | Above raw stock pallet. Approach from above. |
| W2 | Stock pick | (0.4, -0.3, 0.78) | In stock pallet. Gripper closes on billet. |
| W3 | Stock lift | (0.4, -0.3, 0.95) | Lift billet clear of pallet. |
| W4 | Door approach | (-0.3, 0.2, 0.95) | In front of Haas door opening. |
| W5 | Vise approach | (-0.55, 0.3, 0.95) | Above vise, inside enclosure. |
| W6 | Vise place | (-0.55, 0.3, 0.9) | Lower billet into vise jaws. |
| W7 | Vise retreat | (-0.3, 0.2, 0.95) | Retract from enclosure after loading. |
| W8 | Vise pick (unload) | (-0.55, 0.3, 0.9) | Grip finished part in vise. |
| W9 | Finished approach | (0.4, 0.3, 0.95) | Above finished parts pallet. |
| W10 | Finished place | (0.4, 0.3, 0.78) | Place finished part on pallet. |
| W11 | Finished retreat | (0.4, 0.3, 0.95) | Clear of pallet. Return to W0 or W1. |

---

## 5. Cycle Sequence (State Machine)

### 5.1 Complete Cycle Definition

```
STATE MACHINE: CNC Tending Cycle

  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │  IDLE ──► PICK_APPROACH ──► PICK_BILLET ──► PICK_LIFT          │
  │                                                                 │
  │  PICK_LIFT ──► CHECK_HAAS_READY ──┬──► WAIT (Haas busy)        │
  │                                   │                             │
  │                                   └──► DOOR_APPROACH (ready)    │
  │                                                                 │
  │  DOOR_APPROACH ──► DISABLE_SPINDLE_EXCLUSION                    │
  │                                                                 │
  │  DISABLE_SPINDLE_EXCLUSION ──► VISE_APPROACH ──► VISE_PLACE     │
  │                                                                 │
  │  VISE_PLACE ──► VISE_CLAMP ──► VISE_RETREAT                    │
  │                                                                 │
  │  VISE_RETREAT ──► ENABLE_SPINDLE_EXCLUSION                      │
  │                                                                 │
  │  ENABLE_SPINDLE_EXCLUSION ──► SIGNAL_HAAS_START                 │
  │                                                                 │
  │  SIGNAL_HAAS_START ──► WAIT_MACHINING (40 min for GL-M4)        │
  │                                                                 │
  │  WAIT_MACHINING ──► HAAS_COMPLETE_SIGNAL                        │
  │                                                                 │
  │  HAAS_COMPLETE_SIGNAL ──► DISABLE_SPINDLE_EXCLUSION             │
  │                                                                 │
  │  DISABLE_SPINDLE_EXCLUSION ──► VISE_APPROACH ──► VISE_UNCLAMP   │
  │                                                                 │
  │  VISE_UNCLAMP ──► PICK_FINISHED ──► VISE_RETREAT                │
  │                                                                 │
  │  VISE_RETREAT ──► ENABLE_SPINDLE_EXCLUSION                      │
  │                                                                 │
  │  ENABLE_SPINDLE_EXCLUSION ──► FINISHED_APPROACH ──► PLACE_DONE  │
  │                                                                 │
  │  PLACE_DONE ──► CHECK_STOCK ──┬──► PICK_APPROACH (more stock)   │
  │                               │                                 │
  │                               └──► CYCLE_COMPLETE (empty)       │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

### 5.2 I/O Protocol (Beelink ↔ Haas ↔ UR10e)

| Signal | Direction | Type | Meaning |
|--------|-----------|------|---------|
| `HAAS_READY` | Haas → Beelink | Digital I/O (M-code) | Haas is idle, door open, safe to enter |
| `HAAS_CYCLE_START` | Beelink → Haas | Digital I/O (M-code) | Start machining cycle |
| `HAAS_CYCLE_COMPLETE` | Haas → Beelink | Digital I/O (M-code) | Machining done, door opening |
| `VISE_CLAMP` | Beelink → Vise | Pneumatic solenoid via DIO | Clamp vise jaws |
| `VISE_UNCLAMP` | Beelink → Vise | Pneumatic solenoid via DIO | Open vise jaws |
| `HEARTBEAT` | Beelink → Relay → UR10e | 100ms pulse | Safety heartbeat (always active) |
| `GRIPPER_CLOSE` | Beelink → UR10e (via Invariant) | URScript command | Close Schunk gripper |
| `GRIPPER_OPEN` | Beelink → UR10e (via Invariant) | URScript command | Open Schunk gripper |

### 5.3 Invariant Checkpoints Per Cycle

Every robot movement command passes through Invariant. In a single load/unload cycle, Invariant validates approximately:

| Phase | Commands | Key Checks |
|-------|---------|------------|
| Pick billet (W0→W1→W2→W3) | ~20-30 waypoint commands | P1 (joint limits), P2 (velocity), P5 (workspace), P6 (exclusion - floor zone) |
| Enter Haas (W4→W5→W6) | ~15-20 commands | P6 (spindle exclusion DISABLED), P2 (velocity scaled in proximity zone) |
| Exit Haas (W6→W7) | ~10 commands | P6 (re-enabled after exit) |
| Unload part (W4→W5→W8→W7) | ~20 commands | Same as enter + P3 (torque check on part grip) |
| Place finished (W9→W10→W11) | ~15-20 commands | P5 (workspace), P6 (exclusion zones) |
| **Total per cycle** | **~80-120 validated commands** | **All checks run on every command** |

Over 1M simulation episodes with ~100 commands each = **~100M individual Invariant validation decisions.** Each one is cryptographically signed and logged.

---

## 6. Isaac Sim Environment Setup

### 6.1 Required Assets

| Asset | Source | Format |
|-------|--------|--------|
| UR10e robot model | NVIDIA Isaac Sim asset library (built-in) | USD/URDF |
| Haas VF-2 enclosure | Custom rigid body model (simplified AABB) | USD |
| Pneumatic vise | Custom articulated joint (open/close) | USD |
| Schunk gripper | NVIDIA Isaac Sim / Robotiq 2F (close enough) | USD |
| 316L billet (GL-M4) | Simple box primitive (0.127 x 0.076 x 0.051 m, 1.6 kg) | USD |
| Stock pallet | Simple box with grid slots | USD |
| Finished parts pallet | Simple box with grid slots | USD |
| Shop floor | Ground plane with concrete texture | USD |

### 6.2 Physics Configuration

| Parameter | Value |
|-----------|-------|
| Simulation timestep | 1/120 s (120 Hz) |
| Physics solver | PhysX (GPU-accelerated) |
| Gravity | -9.81 m/s² (Z-down) |
| Friction (billet-gripper) | μ_s = 0.4, μ_k = 0.3 |
| Friction (billet-vise) | μ_s = 0.6, μ_k = 0.5 |
| UR10e control mode | Joint position control |
| Gripper control mode | Binary (open/close) |

### 6.3 Environment Script Structure

```python
# Isaac Lab environment for Good Luck LLC CNC tending cell
#
# File: envs/good_luck_cnc_tending.py

class GoodLuckCncTendingEnv:
    """
    Isaac Lab environment for UR10e + Haas VF-2 CNC tending.
    
    The environment:
    1. Spawns the UR10e, Haas enclosure, vise, pallets, and billets
    2. Receives joint commands from Invariant (via Unix socket IPC)
    3. Steps the physics simulation
    4. Returns joint states, end-effector position, and force/torque
    5. Manages Haas state machine (idle → cutting → complete)
    
    Invariant runs as an external process, connected via Unix socket.
    The environment does NOT make safety decisions — Invariant does.
    """
    
    def __init__(self, num_envs=1):
        # Load UR10e URDF
        # Place Haas enclosure at (-0.8, 0.3, 0)
        # Place vise at (-0.55, 0.3, 0.9)
        # Place stock pallet at (0.4, -0.3, 0.75)
        # Place finished pallet at (0.4, 0.3, 0.75)
        # Load N billets on stock pallet
        pass
    
    def step(self, joint_positions):
        # Apply joint positions to UR10e
        # Step PhysX
        # Return observation: joint states + EE position + F/T
        pass
    
    def get_haas_state(self):
        # Return current Haas state (IDLE, CUTTING, COMPLETE)
        # In simulation, this is a timer-based state machine
        pass
```

---

## 7. Invariant ↔ Isaac Sim Bridge

### 7.1 Architecture

```
┌─────────────────────┐                    ┌─────────────────────┐
│                     │                    │                     │
│  ISAAC SIM          │                    │  INVARIANT           │
│  (Python)           │                    │  (Rust)              │
│                     │   Unix Socket      │                     │
│  Physics engine     │◄──────────────────►│  Validator           │
│  UR10e model        │   JSON messages    │  Authority           │
│  Haas state machine │                    │  Watchdog            │
│  Billet physics     │                    │  Audit               │
│                     │                    │  Campaign runner     │
│  Sends:             │                    │  Receives:           │
│   - Joint states    │                    │   - Joint states     │
│   - EE position     │                    │   - Haas state       │
│   - F/T feedback    │                    │                      │
│   - Haas state      │                    │  Sends:              │
│                     │                    │   - Validated joint  │
│  Receives:          │                    │     commands (signed) │
│   - Joint commands  │                    │   - OR rejection     │
│     (from Invariant)│                    │                      │
│                     │                    │                      │
└─────────────────────┘                    └─────────────────────┘
```

### 7.2 Message Protocol (JSON over Unix Socket)

**Isaac → Invariant (observation):**
```json
{
  "type": "observation",
  "timestamp_ns": 1234567890,
  "joint_states": {
    "shoulder_pan_joint": {"position": 0.0, "velocity": 0.0, "effort": 0.0},
    "shoulder_lift_joint": {"position": -1.571, "velocity": 0.0, "effort": 0.0},
    "elbow_joint": {"position": 1.571, "velocity": 0.0, "effort": 0.0},
    "wrist_1_joint": {"position": -1.571, "velocity": 0.0, "effort": 0.0},
    "wrist_2_joint": {"position": 0.0, "velocity": 0.0, "effort": 0.0},
    "wrist_3_joint": {"position": 0.0, "velocity": 0.0, "effort": 0.0}
  },
  "end_effector_position": [0.0, -0.3, 1.2],
  "force_torque": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
  "haas_state": "IDLE",
  "gripper_state": "OPEN",
  "billet_in_gripper": false,
  "billets_remaining": 15
}
```

**Invariant → Isaac (command):**
```json
{
  "type": "command",
  "timestamp_ns": 1234567891,
  "target_joint_positions": {
    "shoulder_pan_joint": 0.1,
    "shoulder_lift_joint": -1.5,
    "elbow_joint": 1.6,
    "wrist_1_joint": -1.571,
    "wrist_2_joint": 0.0,
    "wrist_3_joint": 0.1
  },
  "gripper_command": "CLOSE",
  "haas_command": null,
  "vise_command": null,
  "invariant_verdict": "approved",
  "invariant_signature": "base64_ed25519_signature..."
}
```

**Invariant → Isaac (rejection):**
```json
{
  "type": "rejection",
  "timestamp_ns": 1234567891,
  "reason": "P6: end effector at [-0.7, 0.3, 1.1] is inside exclusion zone 'haas_spindle_area'",
  "check_failed": "P6",
  "safe_stop_commanded": false
}
```

---

## 8. Simulation Campaign: 1M Episodes

### 8.1 Campaign Configuration

```yaml
# campaigns/good_luck_1m.yaml
campaign:
  name: "Good Luck LLC CNC Tending - 1M Validation"
  description: "1 million episodes validating Invariant on UR10e + Haas VF-2 CNC tending cell"
  profile: "profiles/ur10e_cnc_tending.json"
  total_episodes: 1_060_000
  parallel_envs: 64
  seed: 42
  deterministic: true

scenarios:
  - name: "normal_cycle"
    weight: 0.01
    episodes: 10_000
    description: "Standard load/unload cycles. No faults."
    
  - name: "reachability"
    weight: 0.0005
    episodes: 500
    description: "Verify all waypoints reachable without collision."

  - name: "adversarial_joint_commands"
    weight: 0.47
    episodes: 500_000
    description: "Random illegal joint positions, velocities, torques injected."
    injections:
      - type: "random_joint_position"
        range: [-10.0, 10.0]
      - type: "random_velocity"
        range: [-20.0, 20.0]
      - type: "random_torque"
        range: [-500.0, 500.0]

  - name: "exclusion_zone_violation"
    weight: 0.19
    episodes: 200_000
    description: "Attempt to enter Haas spindle area during cut."
    injections:
      - type: "target_exclusion_zone"
        zone: "haas_spindle_area"
        
  - name: "fault_injection"
    weight: 0.09
    episodes: 100_000
    description: "Gripper drop, part misplace, force anomalies."
    injections:
      - type: "gripper_slip"
        probability: 0.3
      - type: "force_spike"
        magnitude: 200.0
        probability: 0.2

  - name: "watchdog_heartbeat"
    weight: 0.05
    episodes: 50_000
    description: "Kill heartbeat at random points. Robot must stop."
    injections:
      - type: "heartbeat_kill"
        timing: "random"

  - name: "authority_violation"
    weight: 0.09
    episodes: 100_000
    description: "Attempt commands without valid PIC chain or with escalated privileges."
    injections:
      - type: "invalid_authority"
        modes: ["missing_chain", "forged_signature", "privilege_escalation", "wrong_principal"]

  - name: "full_integration"
    weight: 0.09
    episodes: 100_000
    description: "Complete cycles with random faults from all categories."
    injections:
      - type: "mixed"
        fault_probability: 0.15

success_criteria:
  adversarial_rejection_rate: 1.0
  exclusion_zone_rejection_rate: 1.0
  watchdog_stop_rate: 1.0
  authority_rejection_rate: 1.0
  normal_cycle_completion_rate: 0.95
  max_safe_stop_latency_ms: 200
```

### 8.2 What Each Campaign Proves

| Campaign | Episodes | What It Proves | Pass Criteria |
|----------|---------|----------------|--------------|
| Normal cycle | 10,000 | The cell works. Load/unload completes reliably. | ≥95% completion rate |
| Reachability | 500 | Robot can reach all waypoints without collision. | 100% reachable |
| Adversarial joints | 500,000 | Invariant blocks ALL illegal joint commands. | 100% rejection |
| Exclusion zone | 200,000 | Robot CANNOT enter spindle area during cut. | 100% rejection |
| Fault injection | 100,000 | Invariant detects gripper drops, force spikes. | 100% detection |
| Watchdog | 50,000 | Robot stops within 200ms of heartbeat loss. | 100% stop rate, ≤200ms |
| Authority | 100,000 | Invalid/forged authority chains are rejected. | 100% rejection |
| Full integration | 100,000 | End-to-end with random faults. Zero escapes. | Zero safety escapes |
| **Total** | **1,060,000** | **Invariant is safe for production deployment.** | **Zero violations** |

### 8.3 Estimated Simulation Cost

| Resource | Detail | Cost |
|----------|--------|------|
| Cloud GPU | RunPod A100, 64 parallel envs | $0.80/hr |
| Time for 1M episodes | ~30-50 GPU-hours (headless, no rendering) | $24-$40 |
| Hero video rendering | 10 selected episodes with camera | $2-$5 |
| **Total** | | **< $50** |

### 8.4 Output Artifacts

| Artifact | Format | Size | Where |
|----------|--------|------|-------|
| Invariant audit trail | Signed JSONL | ~2-5 GB | S3 or local |
| Campaign summary | JSON | ~1 MB | Git repo |
| Per-episode results | Compressed JSON | ~500 MB | HuggingFace dataset |
| Hero videos (10) | MP4 | ~500 MB | YouTube |
| Seeds + configs | JSON manifest | ~10 MB | Git repo |
| **Proof package** | PDF report | ~20 pages | Loan application |

---

## 9. What to Build (Remaining Software Work)

### 9.1 Task List (Ordered)

| # | Task | Effort | Files |
|---|------|--------|-------|
| 1 | Create `ur10e_cnc_tending.json` profile | 1 hour | `profiles/ur10e_cnc_tending.json` |
| 2 | Add conditional exclusion zone support | 4-8 hours | `invariant-core/src/physics/exclusion_zones.rs`, `models/command.rs` |
| 3 | Build Isaac Lab Unix socket bridge | 8-16 hours | `invariant-sim/src/isaac/bridge.rs` |
| 4 | Build Isaac Lab CNC tending environment (Python) | 16-24 hours | `isaac/envs/good_luck_cnc_tending.py` |
| 5 | Build the cycle state machine (Beelink coordinator) | 8-12 hours | `invariant-cli/src/commands/tend.rs` or new crate |
| 6 | Write campaign config for 1M episodes | 2 hours | `campaigns/good_luck_1m.yaml` |
| 7 | Run 1M episodes on cloud GPU | 2-4 hours (compute) | RunPod |
| 8 | Generate proof package (report + videos) | 4-8 hours | `campaigns/results/` |

**Total estimated work: 45-75 hours of coding + 4 hours of cloud compute.**

### 9.2 What's Already Done (No Work Needed)

- All 20 physics checks (P1-P20)
- Validator orchestrator with signing
- Watchdog with safe-stop
- Audit system with hash chain + verification
- Authority/PIC chain validation
- Campaign runner framework (scenarios, injection, reporting)
- UR10 base profile
- CLI with validate, audit, verify, campaign commands

---

## 10. Sim-to-Real Transfer Plan

### 10.1 What Transfers 100%

| Component | Sim | Real | Changes? |
|-----------|-----|------|----------|
| Invariant binary | Rust binary on dev machine | Same binary on Beelink | None |
| UR10e profile JSON | `ur10e_cnc_tending.json` | Same file on Beelink | None |
| Physics checks | P1-P10 validated in sim | Same checks on Beelink | None |
| Authority chain | Ed25519 validated in sim | Same validation on Beelink | New keys generated |
| Audit system | JSONL on dev machine | JSONL on Beelink SSD | None |
| Watchdog | 100ms heartbeat in sim | 100ms heartbeat via relay | Wire relay hardware |

### 10.2 What Needs Calibration (~2-4 hours on real hardware)

| Component | Sim Value | Real Adjustment |
|-----------|-----------|----------------|
| Waypoint positions (W0-W11) | From simulation coordinates | Re-teach on UR10e pendant (±5-10mm) |
| Gripper force | Simulated | Tune on real Schunk gripper |
| Vise clamp/unclamp timing | Instant in sim | Measure real pneumatic cycle time |
| Haas I/O signal timing | Simulated | Wire real M-code I/O, test handshake |
| Exclusion zone boundaries | From CAD model | Verify with real Haas door position |

### 10.3 What Simulation Cannot Predict

| Effect | Why | Mitigation |
|--------|-----|-----------|
| Chip interference | PhysX doesn't model metal chips | Chip conveyor + manual monitoring first month |
| Coolant spray on gripper | Fluid dynamics not simulated | Gripper has sealed internals; test empirically |
| Thermal drift | Sim doesn't model heat | In-process probing every 5th part |
| Vibration from Haas | Sim doesn't model machine vibration | UR10e has vibration tolerance; verify mounting |

---

*This specification, combined with the existing Invariant build spec (docs/spec.md) and the business plan (business_plan/business_plan.md), forms the complete technical foundation for Good Luck LLC.*
